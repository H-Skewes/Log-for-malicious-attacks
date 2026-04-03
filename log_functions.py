def log_file_event(file_path: str, event_type: str, file_hash: Optional[str]):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO file_events (ts, file_path, event_type, file_hash)
        VALUES (datetime('now'), ?, ?, ?)
    """, (file_path, event_type, file_hash))
    conn.commit()
    conn.close()


def log_alert(file_path: str, raw_line: str, reasons: List[str], action_taken: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO alerts (ts, file_path, raw_line, reasons, action_taken)
        VALUES (datetime('now'), ?, ?, ?, ?)
    """, (file_path, raw_line, "; ".join(reasons), action_taken))
    conn.commit()
    conn.close()


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

                entries.append(CronEntry(
                    schedule=schedule,
                    user=user,
                    command=command,
                    raw_line=raw,
                    source_file=path
                ))
    except (FileNotFoundError, PermissionError):
        pass

    return entries