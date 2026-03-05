# E2E script bytecode (legacy)

Script sources and bytecode have moved to **`../move/`**.

- **Two-signer script**: `../move/two_signer_transfer/` — e2e loads `two_signer_transfer.mv` from that directory.
- **One-signer script**: `../move/one_signer_transfer/` — e2e loads `one_signer_transfer.mv` from that directory.

Run the compile command **inside** each project under `../move/` (e.g. `cd ../move/one_signer_transfer` then `aptos move compile-script --package-dir one_signer_transfer --output-file one_signer_transfer.mv`). See `../move/README.md`.
