"""iam-blast-radius: measure what a compromised principal can actually reach."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("iam-blast-radius")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0+unknown"
