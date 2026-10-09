# Publishing the Python SDK

The Python SDK is versioned independently of the other SDKs in this repository.
Pushing a `python/v*` tag to `TencentBlueKing/bk-kms-sdk` triggers
[the PyPI publishing workflow](../../.github/workflows/python-release.yml).
It checks the tag against `src/bk_kms/_version.py`, runs `make lint` and
`make test` on Linux with Python 3.11 and the GM extra, and builds the wheel and
sdist with `make build`. A separate job uploads those distributions to
<https://pypi.org> using Trusted Publishing. It only publishes from the official
repository.

The existing [Python CI](../../.github/workflows/python.yml) checks the supported
platform matrix on pull requests. Changes to the publishing workflow also
trigger that CI.

## One-time setup

Publishing uses GitHub OIDC, so no PyPI API token is needed in GitHub secrets.

1. Create a GitHub environment named `pypi` in the official repository. Its
   deployment rules must allow `python/v*` tags. Required reviewers are optional;
   configure them only if releases should wait for manual approval.
2. In the PyPI project's **Publishing** settings, add a GitHub Trusted Publisher
   with these exact values:

   | Field | Value |
   | --- | --- |
   | PyPI project | `bk-kms-sdk` |
   | GitHub owner | `TencentBlueKing` |
   | Repository | `bk-kms-sdk` |
   | Workflow filename | `python-release.yml` |
   | Environment | `pypi` |

   If the PyPI project does not exist yet, register a pending publisher with the
   same values from your PyPI account's **Publishing** page.

See the official instructions for
[existing projects](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)
and [new projects](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).
An authorized PyPI project maintainer must complete this setup before the first
release tag is pushed.

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
