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
