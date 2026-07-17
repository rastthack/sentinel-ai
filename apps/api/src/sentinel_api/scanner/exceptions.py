"""Typed scanner failures with safe client-facing messages."""


class ScannerError(Exception):
    """Base scanner error safe to expose through the API."""

    code = "scan_error"
    status_code = 400

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.public_message = message


class RepositoryNotFoundError(ScannerError):
    """The requested repository does not exist."""

    code = "repository_not_found"
    status_code = 404


class RepositoryNotDirectoryError(ScannerError):
    """The requested repository path is not a directory."""

    code = "repository_not_directory"


class UnsafeRepositoryPathError(ScannerError):
    """The requested path violates a repository safety boundary."""

    code = "unsafe_repository_path"


class RepositoryOutsideRootError(ScannerError):
    """The requested repository is outside the configured scan root."""

    code = "repository_outside_scan_root"


class ScanConfigurationError(ScannerError):
    """Server-side scan-root configuration is invalid."""

    code = "scan_configuration_error"
    status_code = 500
