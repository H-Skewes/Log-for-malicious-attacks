def file_hash(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return None


def snapshot_watch_dir() -> Dict[str, Optional[str]]:
    snapshot = {}
    if not os.path.isdir(WATCH_DIR):
        return snapshot

    for name in os.listdir(WATCH_DIR):
        full = os.path.join(WATCH_DIR, name)
        if os.path.isfile(full):
            snapshot[full] = file_hash(full)
    return snapshot


def read_payload_preview(command: str) -> str:
    """
    If command points to a readable script file, read a preview.
    This helps detect behavior inside /tmp payloads instead of only the cron line.
    """
    tokens = command.split()
    for token in tokens:
        if token.startswith("/") and os.path.isfile(token):
            try:
                with open(token, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read(500)
            except Exception:
                return ""
    return ""


def parse_cron_file(path: str) -> List[CronEntry]:
    entries = []

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                raw = line.strip()

                if not raw or raw.startswith("#"):
                    continue

                parts = raw.split()
                if len(parts) < 7:
                    continue

                schedule = " ".join(parts[0:5])
                user = parts[5]
                command = " ".join(parts[6:])
                payload_preview = read_payload_preview(command)

                entries.append(CronEntry(
                    schedule=schedule,
                    user=user,
                    command=command,
                    raw_line=raw,
                    source_file=path,
                    payload_preview=payload_preview
                ))
    except (FileNotFoundError, PermissionError):
        pass

    return entries

def diff_changed_files(old: Dict[str, Optional[str]], new: Dict[str, Optional[str]]) -> List[str]:
    changed = []
    for path, new_hash in new.items():
        if path not in old:
            changed.append(path)
        elif old[path] != new_hash:
            changed.append(path)
    return changed