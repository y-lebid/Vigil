# Vigil

![Tests](https://github.com/y-lebid/Vigil/actions/workflows/tests.yml/badge.svg)

Lightweight CLI SIEM for parsing system logs and running rule-based detections.

> **Status: early development (v0.1.0).** The project skeleton, packaging and CI are in place. Log parsing, storage and detection rules are planned. See the [roadmap](docs/SPEC.md#8-етапи-розробки-і-релізи).

## Goals

Vigil reads OpenSSH authentication logs, stores normalised events in SQLite, and flags suspicious patterns such as repeated failed logins from one IP. Detection rules are written in YAML, so they can be read, changed and tested without touching Python code.

It is built to run on an ordinary laptop, without a server or external services.

## Installation

Requires Python 3.10 or newer.

```bash
git clone https://github.com/y-lebid/Vigil.git
cd Vigil
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .
```

## Development

```bash
pip install pytest
pytest
```

Every change should pass the test suite before it is committed. CI runs the same tests on Ubuntu and Windows with Python 3.10 and 3.14.

## Platform support

| Platform | Status |
|---|---|
| Linux (Ubuntu) | Tested in CI |
| Windows 10/11 | Tested in CI |
| WSL2 (Ubuntu) | Tested locally |

Features that depend on system services, such as reading `/var/log/auth.log` directly or journald, will be marked as native Linux only.

## Roadmap

| Version | Scope | Status |
|---|---|---|
| v0.1.0 | Project skeleton, packaging, CI | Done |
| v0.2.0 | Event model and OpenSSH parser | Planned |
| v0.3.0 | SQLite storage | Planned |
| v0.4.0 | Rule engine and `ssh_bruteforce` rule | Planned |
| v0.5.0 | Command-line interface | Planned |

The full specification, with requirements and acceptance criteria for each release, is in [docs/SPEC.md](docs/SPEC.md).

## Contributing

This is a personal project, but issues and suggestions are welcome. Please open an issue before starting a large change.

## License

MIT. See [LICENSE](LICENSE).