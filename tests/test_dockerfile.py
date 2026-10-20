"""Assert the Dockerfile's security properties.

These are structural checks on the file, not a built image: this repository's
build environment cannot reach Docker Hub, so the image is built and run in CI
where it can. That split is worth being explicit about. What is verified here is
that the file still says what the README and SECURITY.md claim it says, which is
the part that silently rots when somebody edits it in a hurry.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

DOCKERFILE = Path(__file__).resolve().parents[1] / "Dockerfile"
DOCKERIGNORE = Path(__file__).resolve().parents[1] / ".dockerignore"


@pytest.fixture(scope="module")
def dockerfile() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def test_dockerfile_exists():
    assert DOCKERFILE.exists()


def test_build_is_multi_stage(dockerfile):
    """A single stage image ships the compiler and the source tree. A security
    tool that did that would be making the argument against itself."""
    stages = re.findall(r"^FROM\s+(\S+)(?:\s+AS\s+(\S+))?", dockerfile, re.MULTILINE | re.IGNORECASE)
    assert len(stages) >= 2, "expected a build stage and a runtime stage"
    names = [name for _, name in stages if name]
    assert "build" in names and "runtime" in names


def test_runtime_stage_does_not_install_a_toolchain(dockerfile):
    runtime = dockerfile.split("AS runtime", 1)[1]
    assert "pip install" not in runtime, "the runtime stage must copy the prefix, not install"
    assert "gcc" not in runtime and "build-essential" not in runtime


def test_base_images_are_pinned_to_a_minor_version(dockerfile):
    """`python:latest` makes a rebuild a different image. Every tag here names
    a specific Python minor."""
    for image, _ in re.findall(r"^FROM\s+(\S+)(?:\s+AS\s+(\S+))?", dockerfile, re.MULTILINE | re.IGNORECASE):
        assert ":" in image, f"{image} has no tag"
        assert "latest" not in image, f"{image} is a floating tag"
        assert re.search(r":\d+\.\d+", image), f"{image} does not pin a minor version"


def test_container_runs_as_a_non_root_user(dockerfile):
    assert re.search(r"^USER\s+(?!root\b)\S+", dockerfile, re.MULTILINE), "no non root USER directive"
    assert "--uid 10001" in dockerfile
    assert "nologin" in dockerfile, "the service account should not have a shell"


def test_user_directive_comes_after_the_copy(dockerfile):
    """Dropping privileges before copying would leave the files unreadable, and
    dropping them after everything is the point."""
    user_at = dockerfile.index("\nUSER ")
    copy_at = dockerfile.rindex("COPY --from=build")
    assert user_at > copy_at


def test_no_secrets_or_credentials_are_baked_in(dockerfile):
    """The service holds no credentials by design. An ARG or ENV that looked
    like one would contradict SECURITY.md."""
    forbidden = ("AWS_ACCESS_KEY", "AWS_SECRET", "AWS_SESSION_TOKEN", "PASSWORD", "TOKEN=")
    for needle in forbidden:
        assert needle not in dockerfile.upper().replace("PYTHONUNBUFFERED", ""), needle


def test_healthcheck_is_declared(dockerfile):
    assert "HEALTHCHECK" in dockerfile
    assert "/health" in dockerfile


def test_entrypoint_is_the_cli(dockerfile):
    assert re.search(r'ENTRYPOINT\s+\["ibr"\]', dockerfile)


def test_dockerignore_excludes_the_git_directory_and_generated_data():
    """The .git directory carries the whole history and any generated account
    is somebody's IAM configuration. Neither belongs in a build context."""
    ignored = DOCKERIGNORE.read_text(encoding="utf-8").split()
    for entry in (".git", "data/generated", "docs/reachability.json"):
        assert entry in ignored, f"{entry} is not excluded from the build context"
