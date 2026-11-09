# Contributing to LLM Honeypot Hub

Thank you for considering a contribution! 🎉

## Adding a Resource

1. Fork the repo and create a branch: `git checkout -b add/your-resource`
2. Add your entry to the correct table in `README.md` following the existing format.
3. Verify all links are reachable.
4. Open a Pull Request with a brief description.

## Improving the Honeypot Code

1. Fork, branch, and implement your change.
2. Add or update tests in `tests/`.
3. Run `ruff check honeypot/` and fix any lint issues.
4. Run `pytest tests/ -v` and ensure all tests pass.
5. Open a Pull Request against `main`.

## Code Style

- Python 3.11+
- `ruff` for linting (config in `pyproject.toml`)
- Type hints on all public functions
- Docstrings on all public classes and functions

## Security

If you discover a security vulnerability, please **do not** open a public issue.
Email the maintainer directly instead.
