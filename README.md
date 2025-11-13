# GitHub Actions - Commit Signature Verification

A modular GitHub Action that inspects commit signatures and reports whether hardware-backed ED25519-SK/ECDSA-SK (SSH) or vetted GPG keys were used.

## 🎯 Purpose

This action surfaces signature metadata for every commit (push or PR) so reviewers can see whether hardware security keys (YubiKey, etc.) were used. It highlights the algorithms encountered and matches GPG fingerprints against an allow list. Specifically, it tells you when a commit was signed with:
- **ED25519-SK** algorithm (SSH)
- **ECDSA-SK** algorithm (SSH)
- Allowlisted GPG

The action supports both **SSH key signatures** and **GPG signatures**, automatically detecting the signature type and verifying the algorithm used.

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
          allowed-algorithms: 'ED25519-SK,ECDSA-SK'
```

### Option 3: Use Across Repositories

If you push this to a template repository (e.g., `your-org/actions-templates`), you can reference it from other repos:

```yaml
- uses: your-org/actions-templates/.github/actions/verify-commit-signature@main
  with:
    allowed-algorithms: 'ED25519-SK,ECDSA-SK'
```

## 🔧 Usage Examples

### Verify a Specific Commit

```yaml
- uses: ./.github/actions/verify-commit-signature
  with:
    commit-sha: 'abc123def456'
    allowed-algorithms: 'ED25519-SK,ECDSA-SK'
```
