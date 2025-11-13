# GitHub Actions - Commit Signature Verification

A modular GitHub Action that inspects commit signatures and reports whether hardware-backed ED25519-SK/ECDSA-SK (SSH) or vetted GPG keys were used.

## 🎯 Purposesssss

This action surfaces signature metadata for every commit (push or PR) so reviewers can see whether hardware security keys (YubiKey, etc.) were used. It highlights the algorithms encountered and matches GPG fingerprints against an allow list. Specifically, it tells you when a commit was signed with:
- **ED25519-SK** algorithm (SSH or GPG)
- **ECDSA-SK** algorithm (SSH or GPG)

The action supports both **SSH key signatures** and **GPG signatures**, automatically detecting the signature type and verifying the algorithm used.

## 📦 What's Included

- **Composite Action** (`.github/actions/verify-commit-signature/`) - The reusable action
- **Example Workflow** (`.github/workflows/verify-signatures.yml`) - Shows how to use it

## 🚀 Quick Start

### Option 1: Use the Example Workflow

Simply copy `.github/workflows/verify-signatures.yml` to your repository. It will automatically verify all commits on push and pull requests.

### Option 2: Use in Your Own Workflow

```yaml
name: My Workflow

on:
  push:
    branches: [main]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - uses: ./.github/actions/verify-commit-signature
        with:
          gpg-allowed-fingerprints-file: '.github/allowed_gpg_fingerprints'
          allowed-algorithms: 'ED25519-SK,ECDSA-SK'
```

### Option 3: Use Across Repositories

If you push this to a template repository (e.g., `your-org/actions-templates`), you can reference it from other repos:

```yaml
- uses: your-org/actions-templates/.github/actions/verify-commit-signature@main
  with:
    allowed-algorithms: 'ED25519-SK,ECDSA-SK'
```

## 📚 Action Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `commit-sha` | Commit SHA to verify (defaults to HEAD) | No | `HEAD` |
| `allowed-algorithms` | Comma-separated list of allowed SSH algorithms to flag as compliant | No | `ED25519-SK,ECDSA-SK` |
| `gpg-allowed-fingerprints` | Comma/newline separated list of trusted GPG key fingerprints (uppercase). Leave blank to accept any GPG signer. | No | `''` |
| `gpg-allowed-fingerprints-file` | Path to a file (newline-separated fingerprints) that is combined with `gpg-allowed-fingerprints`. | No | `''` |
| `fail-on-policy-violation` | Fail the workflow when an unsigned commit or disallowed algorithm/fingerprint is found. Set to `'false'` for reporting-only mode. | No | `true` |
| `initial-push-scope` | For the first push of a branch (`before=000…`), choose `'full'` to scan the branch history or `'head-only'` to scan only the latest commit. | No | `full` |

## 📤 Action Outputs

| Output | Description |
|--------|-------------|
| `is-signed` | Whether the commit is signed (`true`/`false`) |
| `algorithm` | The signature algorithm used |
| `is-allowed` | Whether the signature uses an allowed algorithm (`true`/`false`) |
| `fingerprint` | Fingerprint of the signing key (if available) |

## 🔧 Usage Examples

### Verify a Specific Commit

```yaml
- uses: ./.github/actions/verify-commit-signature
  with:
    commit-sha: 'abc123def456'
    allowed-algorithms: 'ED25519-SK,ECDSA-SK'
```

### Allow Only ED25519-SK

```yaml
- uses: ./.github/actions/verify-commit-signature
  with:
    allowed-algorithms: 'ED25519-SK'
```

### Use Outputs

```yaml
- id: verify
  uses: ./.github/actions/verify-commit-signature

- name: Check result
  run: |
    echo "Is signed: ${{ steps.verify.outputs.is-signed }}"
    echo "Algorithm: ${{ steps.verify.outputs.algorithm }}"
    echo "Is allowed: ${{ steps.verify.outputs.is-allowed }}"
```

## 📄 JSON Reports & Output

For every run the action prints a human-readable line per commit *and* writes `commit-signature-report.json` in the workspace with a JSON array of entries:

```json
[
  {
    "commit": "3d998730d9d708afc3f773616c66e2ff3027c5a0",
    "is_signed": true,
    "signature_type": "GPG",
    "algorithm": "GPG",
    "fingerprint": "D47C...70F",
    "ssh_algorithm_allowed": false,
    "gpg_fingerprint_allowed": true,
    "notes": ["GPG fingerprint matches allow list"]
  }
]
```

You can archive or forward this file to downstream systems (CloudWatch, SIEMs, etc.) without modifying the action itself.

### Interpreting Console Output

- `✅` — Signed and matches the allow list (SSH algorithm is in `allowed-algorithms`, or GPG fingerprint is present in your allow list).
- `⚠️` — Signed but outside the allow list (e.g., SSH signature without `-SK`, unknown GPG fingerprint) **or** not signed at all.
- `ℹ️` — Informational entries for signatures the parser could not fully classify. These should be rare; turn on `SIGNATURE_DEBUG=1` if you need to troubleshoot.

## 🎯 Restricting GPG Signers

If you rely on GPG-signed commits, define `gpg-allowed-fingerprints` to limit which keys are accepted:

```yaml
- uses: ./.github/actions/verify-commit-signature
  with:
    gpg-allowed-fingerprints: |
      D47C0610BDEAD4D64CAE1917F67E56D797BAD70F
      ABCDEF0123456789ABCDEF0123456789ABCDEF01
```

- Fingerprints are case-insensitive internally, but store them uppercase for clarity.
- To keep the list transparent, add a tracked file (e.g., `.github/allowed_gpg_fingerprints`) and pass `gpg-allowed-fingerprints-file: '.github/allowed_gpg_fingerprints'`.
- Any surrounding punctuation (parentheses, spaces) is stripped automatically before comparison, so you can copy values directly from `git log --show-signature` output.
- If the fingerprint cannot be extracted (e.g., key missing on the runner) the action marks it as “not allowed” in the report.
- When a fingerprint is missing, the JSON report now includes `raw_signature_output` with the exact `git log --show-signature` text so you can see which key Git requested.
- External contributors keep working as usual: unknown fingerprints simply show up as “not in allow list” so reviewers can decide what to do.

## 🔐 Setting Up Commit Signing

### Option 1: SSH Key Signing (Recommended)

SSH key signing is simpler and works well with hardware security keys:

1. **Generate an SSH key on your hardware security key:**
   ```bash
   ssh-keygen -t ed25519-sk -C "your_email@example.com"  # For ED25519-SK
   # or
   ssh-keygen -t ecdsa-sk -b 256 -C "your_email@example.com"  # For ECDSA-SK
   ```

2. **Add your SSH public key to GitHub:**
   - Copy your public key: `cat ~/.ssh/id_ed25519_sk.pub`
   - Go to: GitHub Settings → SSH and GPG keys → New SSH key
   - Paste your public key

3. **Configure Git to use SSH for signing:**
   ```bash
   git config --global gpg.format ssh
   git config --global user.signingkey ~/.ssh/id_ed25519_sk.pub
   git config --global commit.gpgsign true
   ```

### Option 2: GPG Key Signing

1. **Generate a GPG key on your hardware security key:**
   ```bash
   gpg --full-generate-key
   # Select: (1) RSA and RSA (default)
   # Then: (14) Existing key
   # Select your hardware key
   # Choose algorithm: (11) ECC (sign only) or (13) ECC (set your own capabilities)
   # Curve: (1) Curve 25519 (for ED25519-SK) or (2) NIST P-256 (for ECDSA-SK)
   ```

2. **Configure Git to use the key:**
   ```bash
   git config --global user.signingkey YOUR_KEY_ID
   git config --global commit.gpgsign true
   ```

3. **Export and add your public key to GitHub:**
   ```bash
   gpg --armor --export YOUR_KEY_ID
   # Add to: GitHub Settings → SSH and GPG keys → New GPG key
   ```

## 📝 Notes

- Every commit reachable from the triggering push/pull request is inspected (merge commits included) as long as `actions/checkout` runs with `fetch-depth: 0`. For initial pushes where `before` is all zeros, set `initial-push-scope: 'head-only'` if you only want the tip commit scanned.
- The action prints `✅/⚠️/ℹ️` markers and writes `commit-signature-report.json`. With `fail-on-policy-violation: 'true'` (default) any unsigned/disallowed commit causes the job to fail; set it to `'false'` for reporting-only mode.
- Use `allowed-algorithms` to define which SSH key types count as “hardware-backed” for your org (defaults to `ED25519-SK,ECDSA-SK`).
- Use `gpg-allowed-fingerprints`/`file` to highlight known YubiKey-backed GPG keys; unknown fingerprints simply show up as “not in allow list”.
- Need extra diagnostics? Set `SIGNATURE_DEBUG=1` on the step to print detailed parsing logs.
- Want the single-commit step (used for outputs) to stay silent? Leave it as-is. To surface its logs as well, set `SIGNATURE_VERBOSE=1` on the action step.
- By default the action fails the job when a commit is unsigned or outside your allow list (`fail-on-policy-violation: 'true'`). Set it to `'false'` if you only need reporting.

## 🤝 License

This template is provided as-is for use in any project.
