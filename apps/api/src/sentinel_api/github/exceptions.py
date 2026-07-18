"""Safe failures for public GitHub repository URL validation."""


class GitHubUrlError(ValueError):
    """Raised when an input is not a supported public GitHub repository URL."""

    code = "github_url_invalid"
    public_message = "The repository URL must be a public HTTPS GitHub repository URL."

    def __init__(self) -> None:
        super().__init__(self.public_message)
