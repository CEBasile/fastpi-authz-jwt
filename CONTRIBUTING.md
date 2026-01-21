# Contributing

Thanks for considering contributing! A minimal workflow:

- Ensure `pre-commit` is installed and hooks are available. If you use pip:

```bash
pip install pre-commit
pre-commit install
```

- Create a feature branch, run tests and pre-commit hooks locally before pushing:

```bash
git checkout -b feat/description-or-fix
uv run pytest
pre-commit run --all-files
git add .
git commit -m "Describe your change"
git push -u origin feat/description-or-fix
```

- Open a Merge Request (or Pull Request) in your Git hosting UI, include a short description, testing notes, and link any related issues.

Typical MR checklist:

- All tests pass locally (`uv run pytest`).
- `pre-commit` hooks pass (formatting, linting).
- A short changelog/description included in the MR description.
