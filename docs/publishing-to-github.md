# Publishing the repository to GitHub

The official repository is `https://github.com/SyntaX-sudo/BreachFrame`. The
URL appears in the README badges and links, `SECURITY.md`, `Cargo.toml`
(`repository`) and `src-tauri/tauri.conf.json` (`homepage`). When publishing a
fork under another account or organisation, replace it everywhere first:

```bash
# from the repository root (Git Bash / Linux / macOS)
grep -rl "SyntaX-sudo/BreachFrame" --exclude-dir={node_modules,target,dist,.git} . \
  | xargs sed -i 's#SyntaX-sudo/BreachFrame#<owner>/<repo>#g'
```

Then:

```bash
git add .
git commit -m "Initial BreachFrame release candidate"

# with the GitHub CLI
gh repo create <owner>/BreachFrame --public --source . --push

# or manually: create an empty repository on github.com, then
git remote add origin https://github.com/<owner>/BreachFrame.git
git push -u origin main
```

After the first push:

1. The **CI** workflow runs automatically. It covers lint, typecheck, unit tests,
   Rust tests on three OSes, Windows E2E, and installer bundles for five
   targets uploaded as workflow artifacts. The CI badge in the README turns
   green or red based on this run.
2. Configure the `release` environment as described in [releasing.md](releasing.md).
3. Enable *Private vulnerability reporting* (Settings → Security). SECURITY.md
   points to it.
4. Tag `v0.1.0` when you are ready for a first draft release. The release
   badge shows a version only once a release is **published**.

Do not commit:

- `node_modules/`, `target/`, `dist/`, test reports (already in `.gitignore`);
- any `.db` file or real configuration files containing secrets.
