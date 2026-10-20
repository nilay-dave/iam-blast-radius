# Multi stage so the published image carries the application and its runtime
# dependencies and nothing else: no compiler, no build metadata, no source
# tree. A security tool that shipped a fat image would be making the argument
# against itself.
FROM python:3.13-slim AS build

WORKDIR /build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

# Install into a prefix that the runtime stage copies wholesale. Installing the
# project itself, rather than copying the source, means the console script and
# the package metadata that __version__ reads both exist in the final image.
RUN python -m pip install --no-cache-dir --prefix=/install .

FROM python:3.13-slim AS runtime

# A non root user with no home and no shell. The service reads one file and
# answers questions about it; nothing it does needs an interactive account.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin --uid 10001 ibr

COPY --from=build /install /usr/local

# Accounts are mounted here, read only. Nothing is written at runtime.
WORKDIR /data
USER 10001

EXPOSE 8000

# The service holds no credentials and never calls AWS. See SECURITY.md: that
# boundary is why this can run anywhere rather than needing a role with
# iam:List* across the account.
ENV IBR_MAX_HOPS=3 PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"

ENTRYPOINT ["ibr"]
CMD ["--help"]
