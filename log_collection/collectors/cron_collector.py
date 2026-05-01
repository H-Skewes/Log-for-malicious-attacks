import os
import hashlib
from typing import List, Dict, Any, Optional, NamedTuple

from collectors.base_collector import BaseCollector


# Cron files and directories to monitor
WATCH_FILES = [
    "/etc/crontab",
    "/etc/anacrontab",
]

WATCH_DIR = "/etc/cron.d"
SPOOL_DIR = "/var/spool/cron/crontabs"

# Directories considered writable/suspicious for cron payloads
WRITABLE_DIRS = [
    "/tmp",
    "/dev/shm",
    "/var/tmp",
    "/run/user",
    "/home",
]


class CronEntry(NamedTuple):
    """Represents a single parsed cron job entry"""
    schedule: str
    user: str
    command: str
    raw_line: str
    source_file: str
    payload_preview: str


class CronCollector(BaseCollector):
    """
    Detects unauthorized cron job creation by monitoring cron-related
    files for modifications and flagging entries that execute scripts
    from writable directories.
    """

    def __init__(self, vm_ip: str, config: Dict[str, Any] = None):
        super().__init__(vm_ip, config)

        # Baseline hashes of watched files captured at startup
        self._file_baselines: Dict[str, Optional[str]] = {}

        # Baseline snapshot of /etc/cron.d/ contents
        self._cron_dir_baseline: Dict[str, Optional[str]] = {}

        # Baseline snapshot of /var/spool/cron/ contents
        self._spool_baseline: Dict[str, Optional[str]] = {}

        # Baseline cron entries - used to detect newly added entries
        self._known_entries: Dict[str, str] = {}  # raw_line -> source_file

    @property
    def name(self) -> str:
        return "cron_abuse"

    def on_start(self):
        """Capture baseline hashes and cron entries at agent startup"""

        # Hash individual watched files
        for path in WATCH_FILES:
            self._file_baselines[path] = self._file_hash(path)

        # Snapshot watched directory
        self._cron_dir_baseline = self._snapshot_watch_dir(WATCH_DIR)

        # Snapshot spool directory
        self._spool_baseline = self._snapshot_watch_dir(SPOOL_DIR)

        # Capture all currently known cron entries as baseline
        for entry in self._collect_all_entries():
            self._known_entries[entry.raw_line] = entry.source_file

        print(
            f"[{self.name}] Baseline: {len(self._file_baselines)} files, "
            f"{len(self._cron_dir_baseline)} cron.d files, "
            f"{len(self._known_entries)} known cron entries"
        )

    def collect(self) -> List[Dict[str, Any]]:
        """
        Check for cron file modifications and suspicious new entries.
        Called every N seconds by LogAgent.
        """
        events = []

        events.extend(self._check_watched_files())
        events.extend(self._check_cron_dir())
        events.extend(self._check_spool_dir())
        events.extend(self._check_for_new_entries())

        return events

    # ------------------------------------------------------------------
    # Detection Check 1: Hash comparison on individual cron files
    # ------------------------------------------------------------------

    def _check_watched_files(self) -> List[Dict[str, Any]]:
        """Detect modifications to /etc/crontab and /etc/anacrontab"""
        events = []

        for path in WATCH_FILES:
            current_hash = self._file_hash(path)
            baseline_hash = self._file_baselines.get(path)

            # File existed at baseline but hash changed
            if baseline_hash and current_hash and current_hash != baseline_hash:
                events.append(self.build_event(
                    severity="high",
                    description=f"Cron file modified: {path}",
                    file_path=path,
                    baseline_hash=baseline_hash,
                    current_hash=current_hash,
                    detection_method="file_hash_comparison",
                ))
                # Update baseline to avoid repeated alerts for same change
                self._file_baselines[path] = current_hash

            # File newly appeared (wasn't there at baseline)
            elif not baseline_hash and current_hash:
                events.append(self.build_event(
                    severity="medium",
                    description=f"New cron file appeared: {path}",
                    file_path=path,
                    current_hash=current_hash,
                    detection_method="file_hash_comparison",
                ))
                self._file_baselines[path] = current_hash

        return events

    # ------------------------------------------------------------------
    # Detection Check 2: /etc/cron.d/ directory monitoring
    # ------------------------------------------------------------------

    def _check_cron_dir(self) -> List[Dict[str, Any]]:
        """Detect new or modified files in /etc/cron.d/"""
        events = []

        current_snapshot = self._snapshot_watch_dir(WATCH_DIR)
        changed_files = self._diff_changed_files(
            self._cron_dir_baseline, current_snapshot
        )

        for path in changed_files:
            is_new = path not in self._cron_dir_baseline
            action = "created" if is_new else "modified"

            events.append(self.build_event(
                severity="high",
                description=f"Cron drop-in file {action}: {path}",
                file_path=path,
                action=action,
                current_hash=current_snapshot.get(path),
                detection_method="cron_dir_snapshot",
            ))

        # Update baseline
        self._cron_dir_baseline = current_snapshot

        return events

    # ------------------------------------------------------------------
    # Detection Check 3: /var/spool/cron/ monitoring (user crontabs)
    # ------------------------------------------------------------------

    def _check_spool_dir(self) -> List[Dict[str, Any]]:
        """Detect new or modified user crontabs in /var/spool/cron/"""
        events = []

        current_snapshot = self._snapshot_watch_dir(SPOOL_DIR)
        changed_files = self._diff_changed_files(
            self._spool_baseline, current_snapshot
        )

        for path in changed_files:
            username = os.path.basename(path)
            is_new = path not in self._spool_baseline
            action = "created" if is_new else "modified"

            events.append(self.build_event(
                severity="high",
                description=f"User crontab {action} for user: {username}",
                file_path=path,
                username=username,
                action=action,
                current_hash=current_snapshot.get(path),
                detection_method="spool_dir_snapshot",
            ))

        # Update baseline
        self._spool_baseline = current_snapshot

        return events

    # ------------------------------------------------------------------
    # Detection Check 4: Parse entries and flag writable dir execution
    # ------------------------------------------------------------------

    def _check_for_new_entries(self) -> List[Dict[str, Any]]:
        """
        Parse all cron files and flag:
        - Entries not seen at baseline (newly added)
        - Entries executing scripts from writable directories
        """
        events = []

        current_entries = self._collect_all_entries()

        for entry in current_entries:
            is_new = entry.raw_line not in self._known_entries
            executes_from_writable = self._is_writable_dir_execution(entry.command)

            if is_new:
                severity = "critical" if executes_from_writable else "high"
                description = (
                    f"New cron entry detected executing from writable directory: "
                    f"{entry.command}"
                    if executes_from_writable
                    else f"New cron entry detected: {entry.command}"
                )

                events.append(self.build_event(
                    severity=severity,
                    description=description,
                    schedule=entry.schedule,
                    user=entry.user,
                    command=entry.command,
                    source_file=entry.source_file,
                    executes_from_writable=executes_from_writable,
                    payload_preview=entry.payload_preview,
                    detection_method="cron_entry_parse",
                ))

                # Add to known entries to avoid re-alerting
                self._known_entries[entry.raw_line] = entry.source_file

        return events

    # ------------------------------------------------------------------
    # Helpers from Tres's original code, adapted for OOP
    # ------------------------------------------------------------------

    def _file_hash(self, path: str) -> Optional[str]:
        """SHA256 hash a file. Returns None if unreadable."""
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(8192):
                    h.update(chunk)
            return h.hexdigest()
        except (FileNotFoundError, PermissionError, IsADirectoryError):
            return None

    def _snapshot_watch_dir(self, directory: str) -> Dict[str, Optional[str]]:
        """
        Snapshot all files in a directory as path -> hash dict.
        Returns empty dict if directory doesn't exist.
        """
        snapshot = {}
        if not os.path.isdir(directory):
            return snapshot
        try:
            for name in os.listdir(directory):
                full = os.path.join(directory, name)
                if os.path.isfile(full):
                    snapshot[full] = self._file_hash(full)
        except PermissionError:
            pass
        return snapshot

    def _diff_changed_files(
        self,
        old: Dict[str, Optional[str]],
        new: Dict[str, Optional[str]]
    ) -> List[str]:
        """
        Return list of file paths that are new or have changed hash.
        Directly from Tres's diff_changed_files logic.
        """
        changed = []
        for path, new_hash in new.items():
            if path not in old:
                changed.append(path)
            elif old[path] != new_hash:
                changed.append(path)
        return changed

    def _read_payload_preview(self, command: str) -> str:
        """
        If command references a script file, read first 500 chars.
        From Tres's read_payload_preview logic.
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

    def _parse_cron_file(self, path: str) -> List[CronEntry]:
        """
        Parse a cron file into CronEntry objects.
        From Tres's parse_cron_file logic.
        """
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
                    payload_preview = self._read_payload_preview(command)
                    entries.append(CronEntry(
                        schedule=schedule,
                        user=user,
                        command=command,
                        raw_line=raw,
                        source_file=path,
                        payload_preview=payload_preview,
                    ))
        except (FileNotFoundError, PermissionError):
            pass
        return entries

    def _collect_all_entries(self) -> List[CronEntry]:
        """Collect all cron entries from all watched locations"""
        entries = []

        # Parse individual watched files
        for path in WATCH_FILES:
            entries.extend(self._parse_cron_file(path))

        # Parse all files in cron.d
        if os.path.isdir(WATCH_DIR):
            for name in os.listdir(WATCH_DIR):
                full = os.path.join(WATCH_DIR, name)
                if os.path.isfile(full):
                    entries.extend(self._parse_cron_file(full))

        return entries

    def _is_writable_dir_execution(self, command: str) -> bool:
        """Check if command executes a script from a writable directory"""
        for writable in WRITABLE_DIRS:
            if writable in command:
                return True
        return False