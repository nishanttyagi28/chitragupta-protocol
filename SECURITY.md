# Security Policy

## Reporting a vulnerability

Please report suspected security vulnerabilities privately rather than
opening a public GitHub issue. Email **jollytyagi360@gmail.com** with:

- A description of the vulnerability and its potential impact.
- Steps to reproduce (a minimal script against the Python API, CLI, or API
  is ideal).
- Which invariant from [docs/security-model.md](docs/security-model.md),
  if any, you believe is violated.

You should expect an acknowledgment within a few days. This is a
single-maintainer open-source project (not a funded security team), so
response times will vary — please be patient, and thank you for reporting
responsibly rather than publicly.

## Supported versions

This project is at `0.1.0`, an explicitly experimental protocol version
(`schema_version` major `1`). Only the latest published release receives
fixes. There is no long-term-support branch at this stage.

## Scope

In scope: the core protocol (`karmasakshi.domain`, `.crypto`, `.grants`,
`.engine`, `.delegation`, `.stores`, `.audit`), the reference adapters, the
CLI, and the optional FastAPI control plane, as shipped in this
repository.

Out of scope: vulnerabilities in third-party dependencies (report those
upstream — though we'd appreciate a heads-up too), and anything requiring
a threat this project explicitly disclaims in
[docs/threat-model.md](docs/threat-model.md) (e.g. compromise of the host
machine itself, or a deliberately dishonest adapter you wrote).

## No certification claim

This project has not undergone a third-party security audit and makes no
certification claims. See [docs/limitations.md](docs/limitations.md).
