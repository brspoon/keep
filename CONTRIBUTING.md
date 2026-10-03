# Contributing to Keep

Thanks for helping improve Keep. The project is for self-hosters running Keep with Plex and Maintainerr. Contributions should preserve account boundaries, current permissions, CSRF protections, media-deletion safeguards, and the separation between collection Keeps and Library Management.

## Before opening a change

- Check existing issues and the [changelog](CHANGELOG.md) for related work.
- For behavior changes, describe the user impact and include focused tests. Use synthetic examples; never use household data, private artwork, real service responses, credentials, database files, or production logs.
- Keep changes scoped. Do not add network-dependent tests or contact production services from tests.
- For source and dependency changes, preserve applicable notices and update the relevant source/notice inventory. See [source distribution](docs/SOURCE_DISTRIBUTION.md) and its [source acquisition instructions](docs/SOURCE_DISTRIBUTION.md#matching-the-container).
- For image or dependency changes, review [image security](docs/IMAGE_SECURITY.md) and [source distribution requirements](docs/SOURCE_DISTRIBUTION.md#component-licenses-and-redistribution). A passing unit test does not replace native image/security/source gates.
- For API changes, keep the `/api/v1` contract and owner-only `/settings/api-keys` management page in sync with the [API guide](docs/API.md) and [OpenAPI 3.1 specification](static/openapi.json). Breaking changes need a new version namespace.

## Local development

Use Python 3.14 and Node.js 22. From a clean checkout:

```sh
python3.14 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -B -m unittest discover -s tests
node --test tests/test_*.cjs
```

The tests use temporary databases, synthetic data, and mocked service calls. They do not require production credentials or populated user data. Run the relevant focused tests while iterating, then run both complete commands before submitting when practical.

## Pull requests

Explain the problem, the resulting behavior, and how you validated it. Call out migrations, configuration changes, permission changes, and any limits that operators need to know.

Pull requests from forks run the Python and JavaScript tests without repository secrets. Maintainers run the native image, security, and source-distribution checks before a release. You do not need registry or publishing credentials to contribute or run the local tests.

By submitting a contribution, you agree that your contribution is offered under the project's [MIT license](LICENSE). Third-party code, assets, dependencies, and notices remain under their own terms; see [third-party attribution](THIRD_PARTY.md).

## Security reports

Report suspected vulnerabilities through [GitHub's private reporting form](https://github.com/brspoon/keep/security/advisories/new). See [SECURITY.md](SECURITY.md) for what to include and what to do if the form is unavailable. Do not use a public issue or pull request for vulnerability details.
