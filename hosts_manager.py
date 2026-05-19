import os
import ctypes
import logging

log = logging.getLogger("proxyevil.hosts")

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
        return os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'drivers', 'etc', 'hosts')
    return '/etc/hosts'

def update_hosts_file(aliases: dict):
    """
    Update the system hosts file with the given aliases.
    Maintains a block delimited by # --- proxyevil start --- and # --- proxyevil end ---.
    """
    if not is_admin():
        log.warning("[HOSTS] Cannot update hosts file: not running as Administrator/root")
        return

    path = get_hosts_path()
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        log.error(f"[HOSTS] Failed to read {path}: {e}")
        return

    START_MARKER = "# --- proxyevil start ---"
    END_MARKER = "# --- proxyevil end ---"

    # Clean up old block and duplicate manual entries
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
                    break # comment starts
                if domain in aliases:
                    overlap = True
                    break
            if overlap:
                continue # Skip this manual duplicate line
                
        filtered_lines.append(line)

    # Build the new block
    new_block_lines = [START_MARKER]
    for fake in sorted(aliases.keys()):
        new_block_lines.append(f"127.0.0.1\t{fake}")
    new_block_lines.append(END_MARKER)

    # Reconstruct the file content
    clean_content = '\n'.join(filtered_lines).rstrip()
    if clean_content:
        new_content = clean_content + "\n\n" + '\n'.join(new_block_lines) + "\n"
    else:
        new_content = '\n'.join(new_block_lines) + "\n"

    if new_content == content:
        log.debug("[HOSTS] No changes needed in hosts file.")
        return

    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        log.info(f"[HOSTS] Successfully updated {len(aliases)} entries in {path}")
    except Exception as e:
        log.error(f"[HOSTS] Failed to write {path}: {e}")
