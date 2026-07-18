"""Tests for strict, network-free public GitHub URL parsing."""

import pytest

from sentinel_api.github.exceptions import GitHubUrlError
from sentinel_api.github.urls import parse_public_github_repository_url


def test_accepts_and_normalizes_canonical_repository_url() -> None:
    repository = parse_public_github_repository_url("https://github.com/openai/sentinel-ai")

    assert repository.owner == "openai"
    assert repository.repository == "sentinel-ai"
    assert repository.normalized_url == "https://github.com/openai/sentinel-ai.git"
    assert repository.display_name == "openai/sentinel-ai"


def test_accepts_git_suffix_and_keeps_one_suffix_normalized() -> None:
    repository = parse_public_github_repository_url("https://github.com/openai/sentinel-ai.git")

    assert repository.repository == "sentinel-ai"
    assert repository.normalized_url == "https://github.com/openai/sentinel-ai.git"


@pytest.mark.parametrize(
    "value",
    [
        "http://github.com/owner/repository",
        "git@github.com:owner/repository.git",
        "ssh://github.com/owner/repository.git",
        "git://github.com/owner/repository.git",
        "file:///tmp/repository",
        "/Users/example/repository",
        r"C:\repository",
        "https://gitlab.com/owner/repository",
        "https://github.com.evil.example/owner/repository",
        "https://api.github.com/owner/repository",
        "https://user:password@github.com/owner/repository",
        "https://github.com:443/owner/repository",
        "https://github.com/owner/repository/issues",
        "https://github.com/owner/repository/tree/main",
        "https://github.com/owner/repository?ref=main",
        "https://github.com/owner/repository#readme",
        "https://github.com//repository",
        "https://github.com/owner/",
        "https://github.com/owner/repo%2Fescape",
        "https://github.com%2Fevil.example/owner/repository",
        " https://github.com/owner/repository",
        "https://github.com/owner/repository ",
        "https://github.com/owner/repository;parameter",
        "https://github.com/owner/repo\n",
        "https://github.com/owner/\x00repository",
    ],
)
def test_rejects_unsupported_or_ambiguous_url(value: str) -> None:
    with pytest.raises(GitHubUrlError) as raised:
        parse_public_github_repository_url(value)

    assert raised.value.code == "github_url_invalid"
    assert str(raised.value) == GitHubUrlError.public_message


def test_credential_value_is_not_in_exception_text() -> None:
    credential = "private-password-value"

    with pytest.raises(GitHubUrlError) as raised:
        parse_public_github_repository_url(
            f"https://user:{credential}@github.com/owner/repository"
        )

    assert credential not in str(raised.value)
