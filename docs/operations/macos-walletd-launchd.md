# macOS walletd with launchd

Use a user LaunchAgent for a durable local wallet node. The service must run a
verified, versioned binary outside a Git worktree so that builds and worktree
cleanup cannot replace or remove the executable under a running service.

## Runtime layout

```text
/Users/<user>/dev/catomicals/.runtime/
├── bin/catomicals-walletd-<commit>-v<schema>
├── walletd-data/
│   ├── wallet.sqlite3
│   ├── signer.json
│   ├── signer-secrets/
│   └── logs/
└── inquisition-signet-data/
```

The runtime `bin` directory should be mode `0700`; deployed binaries should be
mode `0500`. Never overwrite a deployed filename. Copy a new build under a new
commit/schema name and verify its SHA-256 digest before changing the service.

The LaunchAgent belongs at:

```text
~/Library/LaunchAgents/com.catomicals.walletd.plist
```

Its `ProgramArguments[0]` must be the absolute versioned runtime path. Keep
wallet and Bitcoin data directories absolute, bind the wallet to
`127.0.0.1:18788`, and write stdout/stderr below `walletd-data/logs`. Do not put
RPC cookies, keys, tokens, or passwords in the plist or command arguments.

## Install

1. Build and test the candidate in a worktree.
2. Record the candidate SHA-256 digest.
3. Confirm the destination filename does not exist.
4. Copy the candidate to `.runtime/bin/catomicals-walletd-<commit>-v<schema>`,
   set mode `0500`, and confirm the source and destination digests match.
5. Create or update `com.catomicals.walletd.plist` with the versioned absolute
   path, then validate it with `plutil -lint`.
6. Load it in the current graphical user domain:

   ```sh
   launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.catomicals.walletd.plist"
   ```

7. Verify that `launchctl print`, all three wallet status endpoints, and `lsof`
   report the expected program and exact IPv4 listener.

## Upgrade

Before the maintenance window, record the wallet ID, recovery epoch, address,
group public key, signer set ID/epoch, signer manifest digest, current schema,
and node snapshot. Create and verify a matching database-and-signer backup.
Keep the previous deployed binary alongside that backup.

Copy and verify the new versioned binary before stopping the current agent.
Update only `ProgramArguments[0]`, lint the plist, then reload it:

```sh
launchctl bootout "gui/$(id -u)/com.catomicals.walletd"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.catomicals.walletd.plist"
```

Accept the upgrade only when:

- `GET /api/v1/node/status`, `/api/v1/wallet/status`, and
  `/api/v1/signer/status` return Catomicals JSON;
- the expected schema and complete migration ledger are present;
- SQLite integrity and foreign-key checks pass;
- wallet ID, address, group key, signer set, signer epoch, and signer file
  digests match the baseline;
- the Inquisition snapshot is synchronized and OP_CAT is active;
- `lsof -nP -iTCP:18788 -sTCP:LISTEN` shows walletd on the exact IPv4 loopback
  address; and
- a `launchctl kickstart -k` restart restores the same state.

## Rollback

Treat the executable, SQLite database, signer manifest, and encrypted signer
records as one versioned recovery unit. A binary that only supports schema v3
must never open a schema v4 database.

If the database schema did not change, point the plist back to the previous
versioned binary and reload the agent. If a migration occurred, boot out the
new agent, restore the verified pre-upgrade database and signer recovery unit,
point the plist to the matching tested binary, and bootstrap it again. Preserve
the failed runtime directory for inspection; do not recursively delete it.

Repeat the full acceptance checks after rollback. Do not change the wallet port
or stop unrelated Docker containers to hide a listener conflict.
