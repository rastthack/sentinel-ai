"""Application-memory storage for completed, safe scan responses."""

from threading import Lock

from sentinel_api.scanner.models import RepositoryScanResponse


class CompletedScanStore:
    """Store completed scan responses for follow-up, non-authoritative review.

    This deliberately retains only the public scanner response. Repository source
    contents and filesystem locations are not persisted for reviewer requests.
    """

    def __init__(self) -> None:
        self._scans: dict[str, RepositoryScanResponse] = {}
        self._lock = Lock()

    def save(self, scan: RepositoryScanResponse) -> RepositoryScanResponse:
        """Record one completed scan and return it unchanged."""
        with self._lock:
            self._scans[scan.scan_id] = scan
        return scan

    def get(self, scan_id: str) -> RepositoryScanResponse | None:
        """Return a completed response by ID without changing it."""
        with self._lock:
            return self._scans.get(scan_id)
