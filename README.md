# Vigil

![Tests](https://github.com/y-lebid/Vigil/actions/workflows/tests.yml/badge.svg)

Lightweight CLI SIEM for log parsing and rule-based detection.

## Status

Early development. Currently supports OpenSSH (`auth.log`) parsing and a SQLite-backed event store.

## Installation

```bash
git clone https://github.com/y-lebid/Vigil.git
cd Vigil
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .
```

## Usage

```bash
vigil scan --input auth.log --rules rules/
vigil alerts --since 1h
```

Команди ще не реалізовані, тому залиш приклади тільки коли вони запрацюють, або позначай їх як планові.

## License

MIT
