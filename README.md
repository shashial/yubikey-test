# GitHub Actions - Commit Signature Verification

A modular GitHub Action that inspects commit signatures and reports whether hardware-backed ED25519-SK/ECDSA-SK (SSH) or vetted GPG keys were used.

## 🎯 Purposes

The action surfaces signature metadata for every commit in a push or pull request so reviewers can confirm that hardware security keys (YubiKey, etc.) were used. It highlights the signature type, algorithm, fingerprint, and matches the result against the allow lists you define.

## 🚀 Quick Start

### Option 1: Use the Included Workflow

Copy `.github/workflows/verify-signatures.yml` to your repository. It checks every push and PR with sensible defaults (SK-only SSH algorithms, bundled GPG allow list, `initial-push-scope: head-only`).

### Option 2: Inline in Your Workflow

```yaml
name: verify-signatures

on:
  pull_request:
  push:

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          filter: blob:none

      - name: Import trusted GPG keys
        run: echo "${{ secrets.GPG_PUBLIC_KEYS }}" | gpg --batch --import

      - uses: ./.github/actions/verify-commit-signature
        with:
          allowed-algorithms: 'ED25519-SK,ECDSA-SK'
          initial-push-scope: 'head-only'
```

### Option 3: Reuse Across Repositories

Publish this action in a central repo and reference it elsewhere:

```yaml
- uses: your-org/yubikey-test/.github/actions/verify-commit-signature@main
  with:
    allowed-algorithms: 'ED25519-SK,ECDSA-SK'
    initial-push-scope: 'head-only'
    ignore-github-merge-commits: 'true'
```

## 📚 Action Inputs

| Input | Description | Default |
| --- | --- | --- |
| `commit-sha` | Commit SHA to inspect for outputs (`HEAD` by default). | `HEAD` |
| `allowed-algorithms` | Comma-separated list of SSH algorithms treated as compliant. | `ED25519-SK,ECDSA-SK` |
| `gpg-allowed-fingerprints` | Inline comma/newline-separated list of trusted GPG fingerprints (uppercase hex). | `''` |
| `gpg-allowed-fingerprints-file` | Path to an additional fingerprint file (relative to the workflow repo). | `''` |
| `fail-on-policy-violation` | Fail the job when a commit is unsigned or unapproved. Set to `'false'` for reporting-only mode. | `true` |
| `initial-push-scope` | When pushing a branch for the first time (`before = 000…`), choose `'full'` (scan entire branch) or `'head-only'`. | `full` |
| `ignore-github-merge-commits` | Ignore the synthetic merge commits GitHub creates for PR CI runs. Set to `'false'` to enforce them. | `true` |

`resolve_allowed_gpg_fingerprints` merges (in this order) inline fingerprints, any file you point at, and finally the bundled `.github/actions/verify-commit-signature/allowed_gpg_fingerprints` file. This keeps the allow list centralized while letting individual repos override it when needed.

## 📤 Outputs

| Output | Description |
| --- | --- |
| `is-signed` | `true` if the inspected commit is signed. |
| `algorithm` | Detected algorithm (`ED25519-SK`, `ECDSA-SK`, `GPG`, etc.). |
| `is-allowed` | `true` when the algorithm/fingerprint is compliant. |
| `fingerprint` | SSH key fingerprint or GPG fingerprint, when available. |

## 🔧 Usage Snippets

### Single Commit Audit

```yaml
- uses: ./.github/actions/verify-commit-signature
  with:
    commit-sha: ${{ github.sha }}
    allowed-algorithms: 'ED25519-SK'
```

### Allow-List Overrides

```yaml
- uses: ./.github/actions/verify-commit-signature
  with:
    gpg-allowed-fingerprints: |
      D47C0610BDEAD4D64CAE1917F67E56D797BAD70F
      ABCDEF0123456789ABCDEF0123456789ABCDEF01
```

## 🗂️ JSON Report & Console Output

Every run prints a line per commit (`✅` compliant, `⚠️` violation, `ℹ️` informational) and writes `commit-signature-report.json` in the workspace:

```json
[
  {
    "commit": "41ba5cff6e24d81e241248f79e60db1bda4a0603",
    "is_signed": true,
    "signature_type": "GPG",
    "algorithm": "GPG",
    "fingerprint": "D47C0610BDEAD4D64CAE1917F67E56D797BAD70F",
    "ssh_algorithm_allowed": false,
    "gpg_fingerprint_allowed": true,
    "notes": ["GPG fingerprint matches allow list"]
  }
]
```

When fingerprints are missing, the report includes `raw_signature_output` (the full `git log --show-signature` text) so you can see which key Git requested.

## 🎯 Restricting GPG Signers

- Fingerprints are compared case-insensitively; uppercase keeps things consistent.
- Any punctuation copied from `git log` is stripped automatically.
- External contributors still work: unknown fingerprints appear as `⚠️` entries so reviewers can decide whether to trust or reject them.

### Importing Keys in CI

GitHub runners don’t know your keys. Import them before running the action:

```yaml
- name: Import trusted GPG keys
  run: echo "${{ secrets.GPG_PUBLIC_KEYS }}" | gpg --batch --import
```

Concatenate multiple ASCII-armored keys inside the secret. Once imported, the action can extract fingerprints and match them against the allow list.

## 🔐 Setting Up Signing

See the README sections on SSH signing (ED25519-SK/ECDSA-SK) and GPG signing to configure contributors’ machines. Enforce `commit.gpgsign true` so signatures are created automatically.

## 📝 Notes

- `actions/checkout` must fetch history (use `fetch-depth: 0`). `filter: blob:none` keeps checkouts fast when you only need metadata.
- Initial pushes default to scanning the entire branch; set `initial-push-scope: 'head-only'` if you only care about the latest commit.
- GitHub’s synthetic PR merge commits are ignored by default (`ignore-github-merge-commits: 'true'`). Set it to `'false'` if you trust and want to enforce those signatures (import GitHub’s key `B5690EEEBB952194`).
- `SIGNATURE_DEBUG=1` prints parser traces; `SIGNATURE_VERBOSE=1` makes the single-commit step log even when compliant.
- `fail-on-policy-violation: 'true'` stops the build on violations. Switch to `'false'` to collect reports without blocking merges.
