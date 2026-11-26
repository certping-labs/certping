# Copyright Seaionl Inc. and CertPing contributors
# SPDX-License-Identifier: Apache-2.0

"""Test stand-in for the CertPing DNS token API, used only by the end-to-end lab.

It accepts the same calls the agent's CertPingDnsProvider makes and writes the records into a
zone file that CoreDNS serves authoritatively, so Pebble and the agent's propagation check see
real DNS answers. One zone (LAB_ZONE, default lab.test). No persistence beyond the zone file.
"""
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ZONE = os.environ.get("LAB_ZONE", "lab.test")
ZONE_FILE = os.environ.get("LAB_ZONE_FILE", "/zones/db.lab.test")
NS_IP = os.environ.get("LAB_NS_IP", "172.30.0.53")
APP_IP = os.environ.get("LAB_APP_IP", "172.30.0.10")
PREFIX = "/api/v1/domains/token-api/dns/zones/"

lock = threading.Lock()
records = {}  # id -> {"id", "recordType", "host", "value", "ttl"}
next_id = 1
serial = int(time.time())


def write_zone():
    global serial
    serial += 1
    lines = [
        f"$ORIGIN {ZONE}.",
        f"@ 60 IN SOA ns1.{ZONE}. admin.{ZONE}. {serial} 60 60 600 60",
        f"@ 60 IN NS ns1.{ZONE}.",
        f"ns1 60 IN A {NS_IP}",
        f"app 60 IN A {APP_IP}",
    ]
    for rec in records.values():
        host = rec["host"] or "@"
        value = rec["value"]
        if rec["recordType"] == "TXT":
            value = '"' + value.replace('"', '\\"') + '"'
        if rec["recordType"] == "CNAME" and not value.endswith("."):
            value = value + "."
        lines.append(f"{host} {rec['ttl']} IN {rec['recordType']} {value}")
    tmp = ZONE_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, ZONE_FILE)


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body=None):
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _route(self):
        if not self.headers.get("Authorization", "").startswith("Bearer cpk_live_"):
            self._send(401, {"error": "unauthorized"})
            return False, None
        path = urlparse(self.path).path
        if not path.startswith(PREFIX):
            self._send(404, {"error": "not found"})
            return False, None
        match = re.fullmatch(r"([^/]+)/records(?:/([^/]+))?", path[len(PREFIX):])
        if not match or match.group(1) != ZONE:
            self._send(404, {"error": "zone not found"})
            return False, None
        return True, match.group(2)

    def do_POST(self):
        global next_id
        ok, _ = self._route()
        if not ok:
            return
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        with lock:
            rec_id = str(next_id)
            next_id += 1
            records[rec_id] = {
                "id": rec_id,
                "recordType": body.get("recordType", "TXT"),
                "host": body.get("host", ""),
                "value": body.get("value", ""),
                "ttl": int(body.get("ttl", 60)),
            }
            write_zone()
        self._send(201, records[rec_id])

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ok": True})
            return
        ok, _ = self._route()
        if not ok:
            return
        query = parse_qs(urlparse(self.path).query)
        rtype = query.get("type", [None])[0]
        name = query.get("name", [None])[0]
        with lock:
            items = [r for r in records.values()
                     if (rtype is None or r["recordType"] == rtype) and (name is None or r["host"] == name)]
        self._send(200, {"items": items})

    def do_DELETE(self):
        ok, rec_id = self._route()
        if not ok or rec_id is None:
            if ok:
                self._send(404, {"error": "record id required"})
            return
        with lock:
            records.pop(rec_id, None)
            write_zone()
        self._send(204)

    def log_message(self, fmt, *args):
        print("dnsapi:", fmt % args, flush=True)


if __name__ == "__main__":
    write_zone()
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
