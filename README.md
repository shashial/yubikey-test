# GitHub Actions - Commit Signature Verification

A modular GitHub Action that verifies commits are signed with ED25519-SK or ECDSA-SK algorithms.

## 🎯 Purpose

This action ensures that all commits in your repository are signed using hardware security keys (YubiKey, etc.) with either:
- **ED25519-SK** algorithm (SSH or GPG)
- **ECDSA-SK** algorithm (SSH or GPG)

The action supports both **SSH key signatures** and **GPG signatures**, automatically detecting the signature type and verifying the algorithm used.

## 📦 What's Included

- **Composite Action** (`.github/actions/verify-commit-signature/`) - The reusable action
- **Example Workflow** (`.github/workflows/verify-signatures.yml`) - Shows how to use it

## 🚀 Quick Start

### Option 1: Use theExample Workflow

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
          ssh-allowed-signers-file: '.github/allowed_signers'  # update to match your repo
          fail-on-unsigned: 'true'
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
| `fail-on-unsigned` | Fail if commit is not signed | No | `true` |
| `allowed-algorithms` | Comma-separated list of allowed SSH algorithms to enforce | No | `ED25519-SK,ECDSA-SK` |
| `ssh-allowed-signers` | Inline contents of an `allowed_signers` file (principal + SSH public key pairs). Needed for full SSH verification. | No | `''` |
| `ssh-allowed-signers-file` | Path to an `allowed_signers` file in your repo (overrides `ssh-allowed-signers`). Needed for full SSH verification. | No | `''` |

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

### Non-Fatal Check (Warning Only)

```yaml
- uses: ./.github/actions/verify-commit-signature
  with:
    fail-on-unsigned: 'false'
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

## 🗂️ Providing SSH Allowed Signers

Git can only **cryptographically verify** SSH signatures when it knows which principals are trusted. Provide an `allowed_signers` file (the same format used by `ssh-keygen`) either inline through `ssh-allowed-signers` or by pointing the action at a file with `ssh-allowed-signers-file`:

```
dev@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC7...
dev@example.com sk-ssh-ed25519@openssh.com AAAAE2V...... comment
```

- When using `ssh-allowed-signers`, store the contents in a secret and pass it as a multi-line string.
- When you already keep an `allowed_signers` file in the repo, set `ssh-allowed-signers-file: '.github/allowed_signers'` (or similar) so every repository that reuses the action shares the same list.
- Each line must contain a principal followed by the corresponding SSH public key. Git uses the commit author email as the principal by default, so ensure they match.

Without this file GitHub Actions cannot cryptographically verify SSH signatures. The action will still detect the algorithm type and fingerprint, but results will be marked with a warning to highlight that verification was skipped.

### Handling Warning-Only Runs

- If you run the action without configuring an `allowed_signers` file, expect log lines like:
  `⚠️ <commit> - ED25519-SK ... [SSH signature detected but allowed_signers file missing on runner]`.
- These warning runs still protect you by detecting the algorithm that was used, but they **do not** cryptographically prove the identity of the signer.
- Add `ssh-allowed-signers` / `ssh-allowed-signers-file` as soon as possible so merges in downstream repositories fail instead of warn when signatures go missing.

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

- The action automatically verifies every commit included in the triggering push or pull request (merge commits included)
- Pull requests compare `base..head`; initial pushes fall back to the entire pushed history
- The action requires `fetch-depth: 0` in checkout to access commit history
- **SSH signatures**: Provide an `allowed_signers` file (see above) for full verification. If it is missing, the action still reports the detected algorithm/fingerprint but marks the result as unverified.
- **GPG signatures**: The action reports the fingerprint even when the public key is not available on the runner. Import the relevant public keys if you also want cryptographic verification to succeed.
- Need extra diagnostics? Set the environment variable `SIGNATURE_DEBUG=1` on the step to print detailed parsing logs for troubleshooting.

## 🤝 License

This template is provided as-is for use in any project.
