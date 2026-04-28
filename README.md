# vaultpatch

> A CLI tool for safely rotating and auditing secrets across HashiCorp Vault namespaces with diff-based previews.

---

## Installation

```bash
pip install vaultpatch
```

Or install from source:

```bash
git clone https://github.com/yourorg/vaultpatch.git && cd vaultpatch && pip install .
```

---

## Usage

Authenticate using your existing Vault token or environment variables (`VAULT_ADDR`, `VAULT_TOKEN`).

**Preview a secret rotation before applying it:**

```bash
vaultpatch rotate --namespace prod/payments --secret db/password --new-value "s3cr3t!" --dry-run
```

**Apply the rotation:**

```bash
vaultpatch rotate --namespace prod/payments --secret db/password --new-value "s3cr3t!"
```

**Rotate multiple secrets from a file:**

```bash
vaultpatch rotate --namespace prod/payments --from-file secrets.yaml --dry-run
```

**Audit recent changes across namespaces:**

```bash
vaultpatch audit --namespace prod/ --since 24h
```

**Example diff preview output:**

```
~ secret/prod/payments/db/password
  - old_value: "p@ssw0rd"
  + new_value: "s3cr3t!"
  
Apply changes? [y/N]:
```

---

## Key Features

- 🔍 Diff-based previews before any secret is modified
- 🔄 Bulk rotation across multiple Vault namespaces
- 📋 Audit log with filterable history
- 🔒 Dry-run mode to validate changes safely

---

## Requirements

- Python 3.9+
- HashiCorp Vault 1.10+
- `hvac` Python client

---

## License

This project is licensed under the [MIT License](LICENSE).
