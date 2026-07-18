"""Safe failures for public GitHub repository URL validation."""


class GitHubUrlError(ValueError):
    """Raised when an input is not a supported public GitHub repository URL."""

    code = "github_url_invalid"
    public_message = "The repository URL must be a public HTTPS GitHub repository URL."

    def __init__(self) -> None:
        super().__init__(self.public_message)


class GitHubAcquisitionError(RuntimeError):
    """Base safe failure for repository acquisition."""

    code = "github_clone_failed"
    public_message = "The repository clone failed."

    def __init__(self) -> None:
        super().__init__(self.public_message)


class GitHubCloneTimedOutError(GitHubAcquisitionError):
    """The clone did not finish within the configured timeout."""

    code = "github_clone_timed_out"
    public_message = "The repository clone timed out."


class GitHubRepositoryUnavailableError(GitHubAcquisitionError):
    """Git could not access the requested repository without authentication."""

    code = "github_repository_unavailable"
    public_message = "The repository is unavailable."


class GitHubRepositoryTooLargeError(GitHubAcquisitionError):
    """The repository exceeds the safe metadata-size limit."""

    code = "github_repository_too_large"
    public_message = "The repository exceeds the maximum supported size."


class GitHubRepositoryTooManyFilesError(GitHubAcquisitionError):
    """The repository exceeds the safe regular-file count limit."""

    code = "github_repository_too_many_files"
    public_message = "The repository contains too many files to scan safely."


class GitHubRepositoryInvalidLayoutError(GitHubAcquisitionError):
    """The acquired repository root cannot be traversed safely."""

    code = "github_repository_invalid_layout"
    public_message = "The repository layout cannot be scanned safely."


class GitHubRepositoryInspectionError(GitHubAcquisitionError):
    """Filesystem metadata could not be inspected safely."""

    code = "github_repository_inspection_failed"
    public_message = "The repository could not be inspected safely."


class GitHubScanError(RuntimeError):
    """Base safe failure for GitHub scan orchestration."""

    code = "github_scan_failed"
    public_message = "The GitHub repository could not be scanned."

    def __init__(self) -> None:
        super().__init__(self.public_message)
