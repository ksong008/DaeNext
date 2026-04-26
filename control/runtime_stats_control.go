/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

func init() {
	// Wire the runtime overview to live pool occupancy in normal control builds.
	runtimeStatsOccupancySnapshot = func() (udpTaskQueues int, udpTaskDropTotal uint64, packetSnifferSessions int) {
		return DefaultUdpTaskPool.Count(), DefaultUdpTaskPool.DropCount(), DefaultPacketSnifferSessionMgr.Count()
	}
}
