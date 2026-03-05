# E2E Move script projects

Two independent Move script projects used by e2e tests. Each project has its own bytecode; e2e loads from the project directory.

| Project | Script | Bytecode file | E2E usage |
|---------|--------|---------------|-----------|
| `one_signer_transfer/` | Single-signer transfer | `one_signer_transfer.mv` | `e2e_script_transfer` (runtime read; skip if missing) |
| `two_signer_transfer/` | Two-signer transfer | `two_signer_transfer.mv` | `e2e_multi_agent_transaction`, `e2e_simulate_multi_agent_then_submit` (runtime read) |

## Compiling

Run the command **inside each project directory** so the output is generated in that directory. Use `--output-file` so the .mv name matches what e2e expects (default would be `script.mv`).

```bash
# Two-signer script: run from inside move/two_signer_transfer/
cd two_signer_transfer
aptos move compile-script --package-dir two_signer_transfer --output-file two_signer_transfer.mv

# One-signer script: run from inside move/one_signer_transfer/ (from move/, do: cd one_signer_transfer)
cd ../one_signer_transfer
aptos move compile-script --package-dir one_signer_transfer --output-file one_signer_transfer.mv
```

E2E loads bytecode from each project directory; no need to copy .mv elsewhere.
