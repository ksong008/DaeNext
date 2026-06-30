#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

readonly utls_module="github.com/refraction-networking/utls"

usage() {
	cat <<'EOF'
Usage:
  ./update-utls.sh [VERSION] [OPTIONS]
  ./update-utls.sh --version VERSION [OPTIONS]

Updates the Go uTLS dependency used by this development-only fixture generator.

VERSION defaults to "latest". It may be any version accepted by:
  go get github.com/refraction-networking/utls@VERSION

Options:
  --version VERSION       uTLS module version or query to update to.
  --generate PATH        Generate fixture JSON at PATH after the update.
  --fingerprints CSV     Fingerprint names passed to the generator.
  --server-name NAME     Fixture SNI passed to the generator.
  --alpn CSV             Fixture ALPN list passed to the generator.
  --no-verify            Skip go test and minimal fixture-generation smoke test.
  --keep-failed          Do not restore go.mod/go.sum if update or verify fails.
  -h, --help             Show this help.

The script restores go.mod/go.sum on failure by default so an incompatible
latest uTLS release does not leave the checkout in a broken state.
EOF
}

target="latest"
target_set=0
generate_out=""
verify=1
keep_failed=0
generator_args=()

while [ "$#" -gt 0 ]; do
	case "$1" in
		-h|--help)
			usage
			exit 0
			;;
		--version)
			if [ "$#" -lt 2 ]; then
				echo "--version requires a value" >&2
				exit 2
			fi
			target="$2"
			target_set=1
			shift 2
			;;
		--generate)
			if [ "$#" -lt 2 ]; then
				echo "--generate requires a path" >&2
				exit 2
			fi
			generate_out="$2"
			shift 2
			;;
		--fingerprints)
			if [ "$#" -lt 2 ]; then
				echo "--fingerprints requires a comma-separated value" >&2
				exit 2
			fi
			generator_args+=("-fingerprints" "$2")
			shift 2
			;;
		--server-name)
			if [ "$#" -lt 2 ]; then
				echo "--server-name requires a value" >&2
				exit 2
			fi
			generator_args+=("-server-name" "$2")
			shift 2
			;;
		--alpn)
			if [ "$#" -lt 2 ]; then
				echo "--alpn requires a comma-separated value" >&2
				exit 2
			fi
			generator_args+=("-alpn" "$2")
			shift 2
			;;
		--no-verify)
			verify=0
			shift
			;;
		--keep-failed)
			keep_failed=1
			shift
			;;
		--)
			shift
			generator_args+=("$@")
			break
			;;
		-*)
			echo "unknown option: $1" >&2
			exit 2
			;;
		*)
			if [ "$target_set" -ne 0 ]; then
				echo "unexpected extra version argument: $1" >&2
				exit 2
			fi
			target="$1"
			target_set=1
			shift
			;;
	esac
done

snapshot_dir="$(mktemp -d)"
restore_on_error=1

restore_module_files() {
	cp "$snapshot_dir/go.mod" go.mod
	if [ -f "$snapshot_dir/go.sum" ]; then
		cp "$snapshot_dir/go.sum" go.sum
	else
		rm -f go.sum
	fi
}

resolved_module_line() {
	local module_version
	local module_sum

	module_version="$(go list -m -f '{{.Path}} {{.Version}}' "$utls_module")"
	module_sum="$(
		go mod download -json "$utls_module" \
			| sed -n 's/^[[:space:]]*"Sum": "\(.*\)",\{0,1\}$/\1/p' \
			| head -n 1
	)"

	if [ -n "$module_sum" ]; then
		printf '%s %s\n' "$module_version" "$module_sum"
	else
		printf '%s\n' "$module_version"
	fi
}

cleanup() {
	status=$?
	if [ "$status" -ne 0 ] && [ "$restore_on_error" -eq 1 ] && [ "$keep_failed" -eq 0 ]; then
		restore_module_files
		echo "restored go.mod/go.sum after failed uTLS update" >&2
	fi
	rm -rf "$snapshot_dir"
	exit "$status"
}

trap cleanup EXIT

cp go.mod "$snapshot_dir/go.mod"
if [ -f go.sum ]; then
	cp go.sum "$snapshot_dir/go.sum"
fi

echo "updating ${utls_module}@${target}"
go get "${utls_module}@${target}"
go mod tidy

if [ "$verify" -eq 1 ]; then
	go test ./...
	go run . -fingerprints chrome_102 >/dev/null
fi

resolved="$(resolved_module_line)"
echo "resolved ${resolved}"

if [ -n "$generate_out" ]; then
	tmp_fixture="$(mktemp)"
	go run . "${generator_args[@]}" > "$tmp_fixture"
	mkdir -p "$(dirname "$generate_out")"
	mv "$tmp_fixture" "$generate_out"
	echo "generated ${generate_out}"
fi

restore_on_error=0
