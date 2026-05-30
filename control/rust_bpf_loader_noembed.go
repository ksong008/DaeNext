//go:build !embedallowed

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

func embeddedRustBpfLoaderPath() (string, error) {
	return "", errEmbeddedRustBpfLoaderUnavailable
}
