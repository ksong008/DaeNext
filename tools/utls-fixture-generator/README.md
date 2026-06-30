# uTLS Fixture Generator

This tool is development/test support only. It must not be used by release
runtime code and must not be packaged into `daed`.

Update the Go uTLS dependency before generating fixtures. The updater defaults
to `latest`, verifies that the generator still compiles and can capture a
minimal ClientHello, and restores `go.mod` / `go.sum` if the selected uTLS
version is incompatible with the local Go toolchain:

```sh
./update-utls.sh latest
```

Or pin a specific version:

```sh
./update-utls.sh v1.3.3
```

The updater can also generate fixture JSON after a successful dependency
update:

```sh
./update-utls.sh latest --generate ../../testdata/utls_clienthello/generated.json
```

Use `--fingerprints`, `--server-name`, and `--alpn` to override generator inputs
for a specific capture run:

```sh
./update-utls.sh v1.3.3 \
  --generate /tmp/utls-clienthello.json \
  --fingerprints chrome_102,safari_16_0
```

The update step is intentionally a script, not logic inside `main`, because
`go run` compiles the generator before `main` executes. Updating
`github.com/refraction-networking/utls` inside `main` would not affect the
current generation run.

The committed default dependency set is kept compatible with the local
development Go toolchain. Newer uTLS versions may require a newer Go toolchain;
in that case update Go first, then run `./update-utls.sh latest`.

The fixture JSON records the resolved uTLS module version and sum in
`source_modules`. That metadata is part of the evidence trail for later typed
Rust template generation; it is not read by release runtime code.
