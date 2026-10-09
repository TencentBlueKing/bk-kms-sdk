# Publishing the Python SDK

The Python SDK is versioned independently of the other SDKs in this repository.
Pushing a `python/v*` tag to `TencentBlueKing/bk-kms-sdk` triggers
[the PyPI publishing workflow](../../.github/workflows/python-release.yml).
It checks the tag against `src/bk_kms/_version.py`, runs `make lint` and
`make test` on Linux with Python 3.11 and the GM extra, and builds the wheel and
sdist with `make build`. A separate job uploads those distributions to
<https://pypi.org> using the `PYPI_TOKEN` GitHub secret. It only publishes from
the official repository.

The existing [Python CI](../../.github/workflows/python.yml) checks the supported
platform matrix on pull requests. Changes to the publishing workflow also
trigger that CI.

## One-time setup

Publishing authenticates to PyPI as `__token__`, with the API token supplied by
the `PYPI_TOKEN` GitHub secret.

1. In your PyPI account's **Account settings → API tokens**, create an API token
   scoped to `bk-kms-sdk`. If the project does not exist yet, use an
   account-scoped token for the first upload, then replace it with a
   project-scoped token once the project exists. Copy the complete token,
   including its `pypi-` prefix.
2. Create a GitHub environment named `pypi` in the official repository. Its
   deployment rules must allow `python/v*` tags. Required reviewers are optional;
   configure them only if releases should wait for manual approval.
3. In the GitHub repository's **Settings → Secrets and variables → Actions →
   New repository secret**, create `PYPI_TOKEN` with the token as its value.
   Alternatively, add it as an environment secret under **Settings → Environments →
   pypi**. Use one location; if both define `PYPI_TOKEN`, the environment secret
   takes precedence.

See the official [PyPI API token instructions](https://pypi.org/help/#apitoken).
Complete this setup before pushing the first release tag. If `PYPI_TOKEN` is
missing or empty, the workflow stops before attempting to upload. The token is
only passed to the publishing job, and the workflow does not print it.

## Release steps

1. Update `src/bk_kms/_version.py` and [CHANGELOG](../CHANGELOG.md), then merge the
   release changes and publishing workflow into `master` after CI passes.
2. Tag the tested release commit. For version `1.0.0`, the tag must be exactly
   `python/v1.0.0`. The following commands assume `HEAD` is that release commit
   and `upstream` points to `TencentBlueKing/bk-kms-sdk`:

   ```bash
   git tag -a python/v1.0.0 -m "Python SDK v1.0.0"
   git push upstream refs/tags/python/v1.0.0
   ```

3. Check the **Publish Python SDK to PyPI** run in GitHub Actions and verify the
   published version on PyPI.

Creating a tag locally does not trigger publishing; pushing it does. The
workflow publishes to PyPI without requiring a GitHub Release. A mismatched
tag or failed check stops the upload. Published versions cannot be overwritten;
use a new version and tag for corrections.
