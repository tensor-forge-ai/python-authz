# Security Policy

## Supported Versions

Security fixes are released for the latest minor version only. Version 0.8.0 fixed the findings recorded in [`docs/security.md`](docs/security.md), and earlier versions will not receive backports. Version 0.8.1 fixed a PostgreSQL privilege error of 0.8.0, described in `CHANGELOG.md`.

| Version | Supported |
|---|---|
| 0.9.x | Yes |
| 0.8.x and earlier | No |

## Reporting a Vulnerability

Report a vulnerability privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Please do not open a public issue or pull request for it.

A useful report names the version, the schema and tuples involved, the check that returns the wrong result or fails, and what you expected. A minimal script that reproduces it with `SqliteStorage(":memory:")` is the fastest to act on.

You will receive an acknowledgement within five working days. The fix is developed in a private fork, released together with an advisory that credits the reporter unless they prefer otherwise, and recorded in `CHANGELOG.md` and `docs/security.md`.

## Scope

In scope are wrong authorization decisions, invariants of the schema that writes can break, consistency-token ordering, denial of service through crafted tuples or check arguments, and the FastAPI integration. The responsibilities that remain with the application, listed at the end of `docs/security.md`, are out of scope.
