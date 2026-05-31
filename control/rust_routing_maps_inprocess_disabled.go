//go:build !linux || !cgo || !rust_inprocess

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "fmt"

func rustInprocessRoutingMapAvailable() bool {
	return false
}

func applyKernelRoutingMapsViaRustInprocess(request rustRoutingMapApplyRequest) error {
	return fmt.Errorf("Rust in-process routing map writer is not enabled")
}

func applyKernelRoutingMapsViaRustOwnedInprocess(request rustRoutingMapApplyRequest) error {
	return fmt.Errorf("Rust in-process routing map owner is not enabled")
}

func updateDomainRoutingMapViaRustInprocess(request rustDomainRoutingMapApplyRequest) error {
	return fmt.Errorf("Rust in-process domain routing map writer is not enabled")
}
