"""Strict parsing for public HTTPS GitHub repository URLs without network access."""

from urllib.parse import urlparse

from sentinel_api.github.exceptions import GitHubUrlError
from sentinel_api.github.models import GitHubRepositoryUrl

_CONTROL_CHARACTERS = {chr(value) for value in range(0x00, 0x20)} | {"\x7f"}


def parse_public_github_repository_url(value: str) -> GitHubRepositoryUrl:
    """Validate and normalize one public HTTPS GitHub repository URL.

    Only canonical two-segment GitHub repository URLs are accepted. The parser is
    intentionally pure: it does not resolve DNS, contact GitHub, or invoke Git.
    """
    if not value or value != value.strip() or _contains_control_character(value):
        raise GitHubUrlError()

    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError as error:
        raise GitHubUrlError() from error

    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.params
        or "%" in parsed.netloc
        or "%" in parsed.path
    ):
        raise GitHubUrlError()

    segments = parsed.path.split("/")
    if len(segments) == 4 and segments[-1] == "":
        segments = segments[:-1]
    if len(segments) != 3 or segments[0] != "" or not segments[1] or not segments[2]:
        raise GitHubUrlError()

    owner, repository = segments[1], segments[2]
    if repository.endswith(".git"):
        repository = repository.removesuffix(".git")
    if not repository or _contains_control_character(owner) or _contains_control_character(
        repository
    ):
        raise GitHubUrlError()

    return GitHubRepositoryUrl(
        owner=owner,
        repository=repository,
        normalized_url=f"https://github.com/{owner}/{repository}.git",
        display_name=f"{owner}/{repository}",
    )


def _contains_control_character(value: str) -> bool:
    """Return whether a value contains ASCII control characters."""
    return any(character in _CONTROL_CHARACTERS for character in value)
