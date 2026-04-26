# Adding tapid as a private TAP umbrella submodule

Right now `tapid/` lives as a plain directory inside the umbrella repo. To make it a real **private** submodule (independently versioned, separate private repo on GitHub), do the following.

## 0. One-time auth setup

Private submodules need auth at `git submodule update` time. Pick one:

### SSH (recommended for individuals)

```bash
# verify your GitHub SSH key is set up
ssh -T git@github.com   # should greet you by username
```

Use SSH submodule URL (`git@github.com:EyeRunnMan/tapid.git`). No PAT needed; agent handles it.

### gh CLI credential helper

```bash
gh auth login                     # if not already
gh auth setup-git                  # registers gh as the credential helper
```

Submodule URL can stay HTTPS (`https://github.com/EyeRunnMan/tapid.git`). gh injects your token transparently.

### PAT in URL (CI / cron / containers)

```bash
git config --global url."https://x-access-token:${GH_TOKEN}@github.com/".insteadOf "https://github.com/"
```

Token needs `repo` scope. Don't bake into images.

---

## 1. Push tapid as its own private repo

```bash
cd D:/projects/TAP/monorepo/tapid
git init
git add .
git commit -m "Initial scaffold: spec + skeleton"

# private repo
gh repo create EyeRunnMan/tapid --private --source=. --remote=origin --push
```

Verify:

```bash
gh repo view EyeRunnMan/tapid --json visibility -q .visibility   # PRIVATE
```

## 2. Replace the in-tree directory with a submodule pointer

```bash
cd D:/projects/TAP/monorepo

# detach in-tree copy from git index (keeps files on disk)
git rm -r --cached tapid

# move aside so submodule add can place it
mv tapid ../tapid-staging
git commit -m "Detach tapid from in-tree, prepare for submodule"

# add as submodule (pick ONE URL form — must match the auth method from §0)
git submodule add git@github.com:EyeRunnMan/tapid.git tapid          # SSH
# OR
git submodule add https://github.com/EyeRunnMan/tapid.git tapid       # HTTPS + gh helper / PAT

git commit -m "Add tapid as private submodule"

# clean up staging copy
rm -rf ../tapid-staging
```

## 3. Update umbrella `README.md`

Add row to the topology table:

```
| `tapid/`               | `EyeRunnMan/tapid` (private)                            | Localhost OIDC issuer (mints JWTs that TAP verifies)     |
```

Add a note in cloning section:

```
## Cloning (private submodule access required)

git clone --recurse-submodules git@github.com:EyeRunnMan/tap.git
# or
git clone --recurse-submodules https://github.com/EyeRunnMan/tap.git
```

If contributors get `Permission denied (publickey)` on the tapid submodule, they don't have read access yet — add them via `gh repo edit EyeRunnMan/tapid --add-collaborator <user>` or via a GitHub Team.

## 4. Granting access to others

```bash
# individual
gh repo edit EyeRunnMan/tapid --add-collaborator alice --permission read

# via team (preferred at scale)
gh api orgs/<org>/teams/<team>/repos/EyeRunnMan/tapid -X PUT -f permission=pull
```

## 5. Future updates

```bash
cd tapid
# edit, commit, push
cd ..
git add tapid       # records new submodule commit on umbrella
git commit -m "Bump tapid submodule"
```

## 6. Public umbrella + private submodule — friction warning

If the umbrella `tap` repo is public and `tapid` is private:

- Drive-by clones of the umbrella will fail at the submodule step with `Permission denied`. The umbrella docs should warn: "tapid submodule is private; request access if you need full builds."
- CI workflows in the public umbrella that use `submodules: recursive` need a PAT secret with read access to the private `tapid` repo. Add `TAPID_READ_TOKEN` (or similar) to the umbrella's repo secrets and pass it to `actions/checkout@v4`:

  ```yaml
  - uses: actions/checkout@v4
    with:
      submodules: recursive
      token: ${{ secrets.TAPID_READ_TOKEN }}
  ```

- Consider keeping the umbrella **private too** while tapid is pre-1.0 — simpler, fewer foot-guns.

## 7. Going public later

When you're ready to OSS tapid:

```bash
gh repo edit EyeRunnMan/tapid --visibility public --accept-visibility-change-consequences
```

No submodule rewiring needed. URLs stay the same; auth becomes optional.
