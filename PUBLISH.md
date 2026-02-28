# Publishing OpenSecAgent to PyPI

## What to do on PyPI (you only need one thing)

After creating your account, you **do not** need to touch most of the menu:

| PyPI menu | Do you need it? |
|-----------|------------------|
| **Account settings** | Yes — go to **API tokens** and create a token (see below). |
| **Your organizations** | No — only for grouping multiple projects. Skip. |
| **Your projects** | No — this list fills in *after* you upload. Nothing to enter now. |
| **Publishing** (GitHub, GitLab, Google, ActiveState) | No for first time — that’s for *automated* publishing (e.g. “publish when I push to GitHub”). Optional later. |

**All you need:** an **API token** so your computer (or a script) can upload the package.

1. On PyPI: click your **username** (top right) → **Account settings**.
2. In the left sidebar: **API tokens**.
3. Click **Add API token**.
4. **Token name**: e.g. `opensecagent-upload`.
5. **Scope**: choose **Project: opensecagent** (if the project already exists) or **Entire account** (then restrict later). For a brand‑new project, “Entire account” is fine for the first upload.
6. Click **Create token**. **Copy the token** (it starts with `pypi-`) and store it somewhere safe; PyPI won’t show it again.

---

## One-time setup (on your machine)

1. **Install build tools**:
   ```bash
   pip install build twine
   ```

2. **Keep your API token** handy (the `pypi-...` string you copied).

## Publish (manual)

1. **Bump version** in `pyproject.toml` (`version = "0.2.0"` → e.g. `"0.2.1"`).

2. **Build**:
   ```bash
   python -m build
   ```
   This creates `dist/opensecagent-<version>.tar.gz` and `dist/opensecagent-<version>-py3-none-any.whl`.

3. **Upload to PyPI**:
   ```bash
   twine upload dist/*
   ```
   When prompted, username: `__token__`, password: your PyPI API token.

   Or use env (no prompt):
   ```bash
   export TWINE_USERNAME=__token__
   export TWINE_PASSWORD=pypi-YourTokenHere
   twine upload dist/*
   ```

4. **Test install**:
   ```bash
   pip install opensecagent
   opensecagent config    # wizard
   opensecagent status
   ```

## Test PyPI (optional)

To try the upload on Test PyPI first:

```bash
twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ opensecagent
```

## What is “Publishing” (GitHub / Trusted Publishers) and do I need it?

**Short answer:** No. You can publish **manually** from your laptop with the API token and `twine` (steps above). You can ignore the PyPI “Publishing” page for now.

**What it’s for:**

- **Publishing → GitHub / GitLab / etc.** on PyPI is about **Trusted Publishers**: PyPI can accept uploads that come from a specific GitHub (or GitLab, etc.) workflow, without you putting an API token in the repo. You link your PyPI project to a repo and a workflow name; when that workflow runs (e.g. on release), PyPI trusts it and publishes the package.
- **GitHub Actions** = small “workflows” (YAML files) that run on GitHub’s servers when something happens (e.g. “when I create a release”). A “publish” workflow would run `build` + `twine upload` (or use Trusted Publishers) so you don’t have to run the upload from your own machine.

**When to use it:** When you want “I create a release on GitHub and the package appears on PyPI automatically.” Until then, **manual upload with the API token is enough**.
