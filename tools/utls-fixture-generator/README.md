# uTLS Fixture Generator

This tool is development/test support only. It must not be used by release
runtime code and must not be packaged into `daed`.

Update the Go uTLS dependency before generating fixtures:

```sh
./update-utls.sh latest
```

Or pin a specific version:

```sh
./update-utls.sh v1.3.3
```

Then generate fixture JSON:

```sh
go run . > ../../testdata/utls_clienthello/generated.json
```

The update step is a separate script because `go run` compiles the generator
before `main` executes. Updating `github.com/refraction-networking/utls` inside
`main` would not affect the current generation run.

The committed default dependency set is kept compatible with the local
development Go toolchain. Newer uTLS versions may require a newer Go toolchain;
in that case update Go first, then run `./update-utls.sh latest`.
