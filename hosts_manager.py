import os
import ctypes
import logging
import tempfile
import shutil
import threading
import time

log = logging.getLogger("proxyevil.hosts")

# ── debounce state for high-frequency dynamic-alias updates ──────────────────
# Fix #4: these are module-level globals — two concurrent calls from separate
# test cases in the same process would share state. Safe for production (single
# proxy process) but tests that call update_hosts_file concurrently must either
# mock these globals or run in separate processes.
_pending_lock    = threading.Lock()
_pending_aliases: dict | None = None
_pending_timer:   threading.Timer | None = None
_DEBOUNCE_SECS   = 0.5   # coalesce writes within this window


def is_admin() -> bool:
    """Check if the script is running with administrative/root privileges."""
    try:
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def get_hosts_path() -> str:
    if os.name == 'nt':
        return os.path.join(
            os.environ.get('SystemRoot', 'C:\\Windows'),
            'System32', 'drivers', 'etc', 'hosts',
        )
    return '/etc/hosts'


def _write_hosts_now(aliases: dict) -> None:
    """Internal: build new content and atomically replace the hosts file."""
    path = get_hosts_path()
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        log.error(f"[HOSTS] Failed to read {path}: {e}")
        return

    START_MARKER = "# --- proxyevil start ---"
    END_MARKER   = "# --- proxyevil end ---"

    # Strip old managed block and any manual duplicate entries
    lines = content.split('\n')
    filtered_lines = []
    in_block = False

    for line in lines:
        stripped = line.strip()
        if stripped == START_MARKER:
            in_block = True
            continue
        if stripped == END_MARKER:
            in_block = False
            continue
        if in_block:
            continue

        # Outside block: drop manual legacy entries for our aliases
        parts = stripped.split()
        if len(parts) >= 2 and parts[0] == "127.0.0.1":
            overlap = False
            for domain in parts[1:]:
                if domain.startswith("#"):
                    break
                if domain in aliases:
                    overlap = True
                    break
            if overlap:
                continue

        filtered_lines.append(line)

    # Build the new managed block
    new_block_lines = [START_MARKER]
    for fake in sorted(aliases.keys()):
        new_block_lines.append(f"127.0.0.1\t{fake}")
    new_block_lines.append(END_MARKER)

    clean_content = '\n'.join(filtered_lines).rstrip()
    new_content = (
        (clean_content + "\n\n" if clean_content else "")
        + '\n'.join(new_block_lines) + "\n"
    )

    if new_content == content:
        log.debug("[HOSTS] No changes needed in hosts file.")
        return

    # Atomic write: write to a temp file in the same directory, then rename.
    # On NTFS and ext4 this is a single metadata operation — no partial state.
    hosts_dir = os.path.dirname(path)
    try:
        fd, tmp_path = tempfile.mkstemp(dir=hosts_dir, prefix=".hosts_tmp_")
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as tmp_f:
                tmp_f.write(new_content)
            shutil.move(tmp_path, path)
        except Exception:
            # Clean up the temp file if the move failed
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except Exception as e:
        log.error(f"[HOSTS] Failed to write {path}: {e}")
        return

    log.info(f"[HOSTS] Successfully updated {len(aliases)} entries in {path}")


def update_hosts_file(aliases: dict) -> None:
    """Update the system hosts file with the given aliases.

    Writes are debounced over a short window so that bulk dynamic-alias
    registration (SPOOF_ALL_DOMAINS path) results in a single file write
    rather than one per discovered domain.

    Maintains a block delimited by::

        # --- proxyevil start ---
        # --- proxyevil end ---
    """
    if not is_admin():
        log.warning("[HOSTS] Cannot update hosts file: not running as Administrator/root")
        return

    global _pending_aliases, _pending_timer

    with _pending_lock:
        # Always take the latest alias snapshot
        _pending_aliases = dict(aliases)

        if _pending_timer is not None:
            _pending_timer.cancel()

        def _flush():
            global _pending_aliases, _pending_timer
            with _pending_lock:
                snap = _pending_aliases
                _pending_aliases = None
                _pending_timer   = None
            if snap is not None:
                _write_hosts_now(snap)

        _pending_timer = threading.Timer(_DEBOUNCE_SECS, _flush)
        _pending_timer.daemon = False
        _pending_timer.start()
