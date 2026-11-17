# Dependency updates

User-space dependency updates use the Rust version in `rust-toolchain.toml`.
Apply a three-day publication cooldown to each update command:

```sh
cargo --config 'registry.global-min-publish-age="3 days"' \
  --config 'resolver.incompatible-publish-age="deny"' \
  update -p <crate>
```

Review the full `Cargo.lock` diff, including transitive dependencies, and commit
the lockfile with the corresponding manifest and source changes. Run the release
gate and the native feature checks before accepting the update. Do not delete the
lockfile to force resolution.

If an urgent fix requires a version inside the cooldown, document the reason and
use an exception scoped to that command and exact version:

```sh
cargo --config 'registry.global-min-publish-age="3 days"' \
  --config 'resolver.incompatible-publish-age="allow"' \
  update -p <crate> --precise <version>
```

Review every transitive change in an exception: `allow` applies to that command's
resolution, not only the named crate. Subsequent updates return to `deny`.

These settings belong to update commands, not global Cargo configuration or
ordinary `--locked` builds. Already locked versions remain usable. Registries
without publication timestamps cannot enforce this cooldown; verify the registry
metadata before relying on it. This policy does not manage `cargo install` tools:
keep their versions explicitly pinned. The eBPF and MIPS build-std commands use
the pinned official compiler with bootstrap enabled only for those commands;
neither applies the cooldown to ordinary builds.
