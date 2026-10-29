#!/usr/bin/env python3
"""Read the lab endpoint on stdin, write the rig's devices.json on stdout. The endpoint is never printed elsewhere."""
import json
import sys

endpoint = sys.stdin.read().strip()
if not endpoint.startswith("https://"):
    sys.exit("endpoint must be https://")
base = "/etc/rustopnsmcp/credentials/"
json.dump(
    {
        "version": 1,
        "devices": {
            "opnsense-lab": {
                "endpoint": endpoint,
                "api_key_file": base + "api-key",
                "api_secret_file": base + "api-secret",
                "ca_pem_path": base + "ca.pem",
            }
        },
    },
    sys.stdout,
)
