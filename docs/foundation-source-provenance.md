# Foundation source provenance receipt

- Source task: `task_a1052208df0b4d468f56478ccfdb23ba`
- Repair task: `task_96e2f567e5e34a81ba4fe617b70ce779`
- Checked worktree: `/Users/ghostcorn/dev/catomicals`
- Source-reported paths checked: 34 of 34 present
- Snapshot algorithm: for each path below, in the source task's reported order, emit the lowercase SHA-256, two spaces, and path followed by LF; SHA-256 that complete byte stream.
- Repair snapshot: `28e4339498d83b9ed2d0b3d66449c7baaa8133f06c64578fe863279843b70935`

The repository had no commit history when this repair began, so this receipt
does not claim a retroactive Git lineage. It supplies the missing explicit
source worktree, checks the source task's reported file set against real files,
and freezes the exact repaired inputs used by the fresh verification run.
Ouroboros runtime/control paths are excluded.

```text
033c8ee86d09768311510fe3a80f9582490c01901e1c9f7208bf748d709c115b  .gitignore
ea28b4cd116f4d79ec2ed46898f8ddeba905a6088da958a6ec64431f93c7c4f4  .rustfmt.toml
93107e8f3070712680172002cd17dec48bac589063886011ffba85ebda7c88fb  Cargo.lock
1a3d9083ff4fe72e3e8bbfe6d7988182c71044b2c7e9c3ab0b4e19dd445cbff4  Cargo.toml
4f1ce38b12feb881ebed5fcab8d50a10746862a7b89415a8238013bd913a536b  README.md
fce4c573ff4bed9cac9e1d31878b3c374a4b294b2c7ff90f73189249290a94a2  rust-toolchain.toml
897eade2b34b62a49bd9c396e7f0d9221e60e3e908c6d11bcf7ac088d1241c3d  apps/catomicals-cli/Cargo.toml
9afeadb84233ce01f70684ddf7dabcbd2ab35de0cca284b8cafd67001a67dbbe  apps/catomicals-cli/src/frost_demo.rs
209f3a5cd895fe520e56d5ee04d5b76d4130ac91d81f8237ebbf75a335d7fb9f  apps/catomicals-cli/src/main.rs
c89625102994432fd2688900f33003b9614ec0b691012472ebb7b9bf7f40babe  apps/catomicals-cli/src/node.rs
3dc0f193e07fc22d7b33be613b57d01c31d50ff552d495b6d83f6d455dd11cd6  apps/catomicals-cli/src/wallet.rs
cbb3917eeb8d0fb95802697f5b601369e672210ffca6af1e4219b846ee5afa77  apps/catomicals-cli/src/wallet_serve.rs
457a5768c10a34676b1238462ce3c860203aacbb70b2ad3ab164791c7c950139  config/bitcoin-signet.conf
eab1e00bb365cc3fdfdfcc82a141f666b431e5c4c98bb3560ccf4b6fa4057240  crates/node-client/Cargo.toml
96b67a34aab0f38f2879c2d9a103034e23b8ee426ebe2a3e4473e79c8368250e  crates/node-client/src/deployment.rs
e90cf4ff122263669b02ae09fbd5d60773d5c3c3970e4322c64b3e33f6950c35  crates/node-client/src/lib.rs
f24385adc70fc9966500ce75870e2eeb1d420705455179cb1057f231c4e5f2cd  crates/node-client/src/rpc.rs
246098ee04eca9d0cbd1b662e4bc21e873ceabf2f170e6ec966504cb026409de  crates/node-client/tests/node_identity.rs
9732834bc5b4f98278d0d5f1a47c004c2fc35f1057d243a6eec59b149508c950  crates/threshold-signer/Cargo.toml
29de6545326d60436973c07d445e2d382329f1b440c316150886f7608f7a0a79  crates/threshold-signer/src/lib.rs
5506d9fbe39b5ed943665f901fb9bc6d3ff858e8b0809f88f5d666fd4de93c27  crates/threshold-signer/src/nonce_guard.rs
77f4eee5e08bcc438396074bee430394d490b64be8d773a8fc079ea96f600563  crates/threshold-signer/src/session.rs
24bf1db6d278307a2b9768f7de272b3a8f0d672b7cb0be9d1c9142711cc03449  crates/wallet-core/Cargo.toml
f9992011390fb6f36e8f66542067c60cf8c9516294c860f0172b8e5d76a284cd  crates/wallet-core/src/api.rs
96d472a730bc93bfbf3be175b79144f50c5a31fd2dd5b98dd8c3175af1ff5f47  crates/wallet-core/src/auth.rs
957f565acabb621f6ce994073881c73384f6221ac3f965061be4fabe9ba43591  crates/wallet-core/src/gate.rs
deddecccc84d051155c8e54181b8030e9375cc381bd84c8ec2dcbdaac61d2aa9  crates/wallet-core/src/intent.rs
6cce04b2e880962c2ed6251bdee6efb544c8628ba9accf747617407abd70fa16  crates/wallet-core/src/lib.rs
77f2a4b24c8ec9bafa63ee9209b4df5babefb317b92118f2ace2293c384bb4ac  crates/wallet-core/src/store.rs
ee6f0eb0040b11ccaf18685a394b1dcbb3ed99e63a4f043f791f084ba3b0f19c  crates/wallet-core/tests/authorization_seam.rs
84bf98dc01b59c8d7e6c220a8e4d61a229c236133a5a1f01b57da5576e7f87e9  crates/wallet-core/tests/security_requirements.rs
c05e1392f121a24bf8c3dcf565215caf6406cf9ccf5fc77e84447c266eccb67b  docs/architecture.md
8f47424f257ca63bbe95d9b988d3381c3ec81631a92e66c4379856f226ff1cab  docs/security.md
9abd00707c43676f8e25456b00e0de6c42de831829d1986f7dcff721d91f3462  scripts/install-bitcoin-inquisition.sh
```

## Repair-owned paths

The repair changed the wallet package manifest, authorization/API/gate/library
modules, the two legacy test entry files, the real WebAuthn ceremony test, and
the security document. It added package-internal copies of the legacy tests and
this receipt. No runtime/control path is part of the repair-owned set.
