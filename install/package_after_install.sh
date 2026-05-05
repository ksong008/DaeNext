#!/bin/bash

if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload

	if systemctl is-active --quiet dae; then
		systemctl restart dae.service
		echo "Restarting dae service, it might take a while."
	fi
fi
