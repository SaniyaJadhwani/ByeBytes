#!/usr/bin/env python3 
"""
Secure file/folder wipe utility with strengthened owner checks.

- POSIX: compares numeric UID (st_uid) to the running user's UID.
- Windows: tries Path.owner(), then falls back to PowerShell (Get-Acl) to fetch owner.
- Skips files inside a folder that are not owned by the current user.
- Usage:
    python wipe.py               -> GUI picker
    python wipe.py --file path    -> select file
    python wipe.py --folder path  -> select folder
    python wipe.py path           -> auto-detect file or folder
    python wipe.py --verbose ...  -> print diagnostics while checking ownership
"""
from __future__ import annotations
import os
import sys
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path
import getpass
import platform
import subprocess

# -------------------- Config --------------------
DEFAULT_PASSES = 3
DEFAULT_CHUNK = 1024 * 1024

# -------------------- Logging --------------------
def log_error(e):
    try:
        with open("error_log.txt", "a", encoding="utf-8") as f:
            f.write(str(e) + "\n")
            f.write(traceback.format_exc())
            f.write("\n" + ("-" * 60) + "\n")
    except Exception:
        pass

# -------------------- Ownership helpers --------------------
def _normalize_windows_owner(owner_str: str | None) -> str | None:
    if not owner_str:
        return None
    s = owner_str.replace("/", "\\")
    parts = s.split("\\")
    username = parts[-1] if parts else s
    return username.lower()

def _get_owner_via_powershell(path: Path) -> str | None:
    """
    Use PowerShell's Get-Acl to get file owner without flashing window.
    """
    try:
        p = str(path).replace("'", "''")
        cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command",
               f"(Get-Acl -LiteralPath '{p}').Owner"]

        creationflags = 0
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            creationflags = subprocess.CREATE_NO_WINDOW

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=creationflags
        )

        out = proc.stdout.strip()
        if out:
            return out

        err = proc.stderr.strip()
        if err:
            log_error(f"PowerShell Get-Acl stderr for {path}: {err}")

        return None
    except Exception as e:
        log_error(f"PowerShell fallback failed for {path}: {e}")
        return None

def get_owner_name(path: Path, verbose: bool = False) -> str | None:
    try:
        try:
            owner = path.owner()
            if owner:
                if verbose:
                    print(f"[dbg] Path.owner() -> {owner}")
                return owner
        except Exception as e:
            if verbose:
                print(f"[dbg] Path.owner() raised: {e!r}")

        if os.name != "posix" and platform.system().lower().startswith("win"):
            owner_ps = _get_owner_via_powershell(path)
            if owner_ps:
                if verbose:
                    print(f"[dbg] PowerShell owner -> {owner_ps}")
                return owner_ps

        if os.name == "posix":
            try:
                import pwd
                uid = path.stat().st_uid
                pw = pwd.getpwuid(uid)
                if pw and pw.pw_name:
                    if verbose:
                        print(f"[dbg] pwd owner -> {pw.pw_name}")
                    return pw.pw_name
            except Exception as e:
                if verbose:
                    print(f"[dbg] pwd fallback failed: {e!r}")
                pass

        return None
    except Exception as e:
        log_error(e)
        return None

def current_username() -> str | None:
    try:
        return getpass.getuser()
    except Exception:
        try:
            return os.getlogin()
        except Exception:
            return None

def is_owner(path: Path, verbose: bool = False) -> bool:
    try:
        if os.name == "posix":
            try:
                file_uid = path.stat().st_uid
                current_uid = getattr(os, "geteuid", lambda: os.getuid())()
                if verbose:
                    print(f"[dbg] POSIX uid: file={file_uid}, me={current_uid}")
                return file_uid == current_uid
            except Exception as e:
                if verbose:
                    print(f"[dbg] POSIX uid check failed: {e!r}")

        owner = get_owner_name(path, verbose=verbose)
        cur = current_username()
        if verbose:
            print(f"[dbg] owner raw: {owner!r}, current user: {cur!r}")

        if owner is None or cur is None:
            if verbose:
                print(f"[dbg] Owner or current user unknown; treating as NOT owner")
            return False

        if os.name == "posix":
            return owner == cur

        norm_owner = _normalize_windows_owner(owner)
        if verbose:
            print(f"[dbg] normalized owner -> {norm_owner}, cur.lower() -> {cur.lower()}")
        return norm_owner == cur.lower()
    except Exception as e:
        log_error(f"is_owner failed for {path}: {e}")
        return False

# -------------------- Secure overwrite & removal --------------------
def secure_overwrite_and_remove(path: Path, passes=DEFAULT_PASSES, chunk_size=DEFAULT_CHUNK):
    try:
        length = path.stat().st_size
        with open(path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                remaining = length
                while remaining > 0:
                    write_size = min(chunk_size, remaining)
                    f.write(os.urandom(write_size))
                    remaining -= write_size
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
        try:
            with open(path, "r+b") as f:
                f.seek(0)
                f.write(os.urandom(min(chunk_size, path.stat().st_size or 1)))
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
        except Exception:
            pass
        path.unlink()
    except Exception as e:
        try:
            path.chmod(0o600)
            path.unlink()
        except Exception as e2:
            raise RuntimeError(f"Failed to securely remove {path}: {e}") from e2

def wipe_file(path: Path, passes=DEFAULT_PASSES, chunk_size=DEFAULT_CHUNK):
    try:
        secure_overwrite_and_remove(path, passes=passes, chunk_size=chunk_size)
        print(f"[+] Wiped: {path}")
    except Exception as e:
        print(f"[!] Error wiping {path}: {e}")
        log_error(e)

# -------------------- Folder wiping --------------------
def wipe_folder(folder: Path, passes=DEFAULT_PASSES, chunk_size=DEFAULT_CHUNK, verbose: bool = False):
    if not folder.exists():
        print(f"[!] Error: {folder} not found")
        return

    if not is_owner(folder, verbose=verbose):
        owner = get_owner_name(folder, verbose=verbose) or "<unknown>"
        cur = current_username() or "<unknown>"
        message = (
            f"You are not the owner of the target folder.\n\n"
            f"Target folder: {folder}\n"
            f"Folder owner: {owner}\n"
            f"Current user: {cur}\n\n"
            "Only the owner can wipe this folder. Operation aborted."
        )
        print("[!] " + message)
        try:
            messagebox.showerror("Permission denied", message)
        except Exception:
            pass
        return

    confirm = messagebox.askyesno(
        "Confirm wipe",
        f"You're about to permanently wipe ALL files inside:\n\n{folder}\n\nThis action is irreversible.\nDo you want to continue?"
    )
    if not confirm:
        print("[*] Wipe cancelled by user.")
        return

    skipped = []
    errors = []
    for root, dirs, files in os.walk(folder, topdown=False):
        root_path = Path(root)
        for file in files:
            file_path = root_path / file
            try:
                if is_owner(file_path, verbose=verbose):
                    wipe_file(file_path, passes=passes, chunk_size=chunk_size)
                else:
                    skipped.append(str(file_path))
                    print(f"[-] Skipped (not owner): {file_path}")
            except Exception as e:
                errors.append((str(file_path), str(e)))
                log_error(e)
        for d in dirs:
            dir_path = root_path / d
            try:
                if is_owner(dir_path, verbose=verbose):
                    try:
                        dir_path.rmdir()
                    except OSError:
                        pass
                else:
                    skipped.append(str(dir_path))
                    print(f"[-] Skipped directory (not owner): {dir_path}")
            except Exception as e:
                errors.append((str(dir_path), str(e)))
                log_error(e)

    try:
        if is_owner(folder, verbose=verbose):
            try:
                folder.rmdir()
            except OSError:
                pass
    except Exception as e:
        log_error(e)
        errors.append((str(folder), str(e)))

    print(f"[✓] Wipe finished for: {folder}")
    if skipped:
        print(f"[!] Skipped {len(skipped)} items not owned by you.")
    if errors:
        print(f"[!] Encountered {len(errors)} errors (see error_log.txt).")

# -------------------- GUI pickers --------------------
def choose_file_or_folder_gui():
    root = tk.Tk()
    root.withdraw()
    resp = messagebox.askquestion("Select target", "Do you want to select a single FILE?\n\n(Choose 'No' to pick a folder.)")
    if resp == "yes":
        path = filedialog.askopenfilename(title="Select File to Wipe")
        return Path(path) if path else None
    else:
        path = filedialog.askdirectory(title="Select Folder to Wipe")
        return Path(path) if path else None

# -------------------- Main --------------------
def main():
    try:
        root = tk.Tk()
        root.withdraw()

        argv = sys.argv[1:]
        verbose = False
        target_path = None

        if "--verbose" in argv:
            verbose = True
            argv = [a for a in argv if a != "--verbose"]

        if len(argv) >= 2 and argv[0] in ("--file", "--folder"):
            target_path = argv[1]
        elif len(argv) == 1:
            target_path = argv[0]
        else:
            chosen = choose_file_or_folder_gui()
            if not chosen:
                messagebox.showinfo("Canceled", "No file/folder selected. Exiting.")
                return
            target_path = str(chosen)

        if not target_path:
            messagebox.showinfo("Canceled", "No file/folder selected. Exiting.")
            return

        target = Path(target_path)
        if not target.exists():
            messagebox.showerror("Error", f"Path does not exist:\n{target_path}")
            return

        if target.is_file():
            if verbose:
                print(f"[dbg] Checking ownership for file: {target}")
            if not is_owner(target, verbose=verbose):
                owner = get_owner_name(target, verbose=verbose) or "<unknown>"
                cur = current_username() or "<unknown>"
                messagebox.showerror(
                    "Permission denied",
                    f"You are not the owner of the file.\n\nFile: {target}\nOwner: {owner}\nCurrent user: {cur}"
                )
                return
            if messagebox.askyesno("Confirm", f"Do you want to permanently wipe the file?\n\n{target}"):
                wipe_file(target)
                messagebox.showinfo("Success", f"File wiped:\n{target}")
            else:
                messagebox.showinfo("Canceled", "Operation canceled by user.")
        else:
            if verbose:
                print(f"[dbg] Checking ownership for folder: {target}")
            wipe_folder(target, verbose=verbose)

    except Exception as e:
        log_error(e)
        try:
            messagebox.showerror("Unexpected Error", f"An error occurred. See error_log.txt for details.")
        except Exception:
            print("An error occurred. See error_log.txt for details.")
        return

if __name__ == "__main__":
    main()
