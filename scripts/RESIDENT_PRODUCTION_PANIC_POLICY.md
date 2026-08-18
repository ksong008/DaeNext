# Resident production panic policy

The resident production panic gate is a continuous check, not a one-time cleanup.
`scripts/check_resident_production_panics.sh` runs Clippy for every resident
production target and compares `unwrap_used` and `expect_used` diagnostics with
`scripts/resident_production_panic_baseline.tsv`.

An approved entry must be a deliberate internal invariant. Operations that
consume configuration, subscription data, DNS answers, or remote peer input
must return an error instead of being added to the baseline. Tests may use
`unwrap` and `expect`; the repository-level `clippy.toml` declares that test
policy explicitly.

The gate rejects new diagnostics, budget increases, malformed entries, missing
source files, and baseline entries that no longer correspond to a diagnostic.
The current focused gate covers resident production targets and the two
Clippy panic lints. The workspace release gate separately runs all-target
Clippy; additional panic classes must be introduced with an audited baseline,
not silently ignored.
