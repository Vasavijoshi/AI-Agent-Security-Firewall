"""Identity's admin surface for digest pins: a CLI, not a network listener.

Run via, e.g.:
    docker compose exec identity python -m identity.admin_cli list-pins
    docker compose exec identity python -m identity.admin_cli clear-pin agent

# WHY a CLI and not a loopback-bound (127.0.0.1) HTTP endpoint (pre-M3 ruling, round 5): identity
# is agent-net-only (see issuer.py's module WHY) — and once identity lives on agent-net, nothing
# bound to a port on identity can be "unreachable from agent-net" as a topology fact, because
# agent-net members can always reach each other's ports directly. A loopback bind would face the
# exact test-methodology trap that already produced one false "reachable" finding for pep's admin
# port: the agent container's HTTP_PROXY still points at pep:8081, so a plain curl "to" identity's
# admin port would be silently redirected through pep's bypass-catch listener and come back with a
# misleading 403 — a signal that looks like "reachable, denied" but never actually tested the
# target at all (see docs/verification-log.md, Verification 2). A CLI with no listening socket has
# no such trap: `docker compose exec` requires Docker daemon access, which the agent container
# fundamentally doesn't have (no docker.sock mount, no way to exec into a sibling container) — so
# there is no reachability question to even ask, rather than one that needs a careful test to
# answer correctly.
"""

from __future__ import annotations

import os
import sys

import identity.store as store

DB_PATH = os.environ.get("IDENTITY_DB_PATH", "/data/identity.db")

_USAGE = "usage: python -m identity.admin_cli [list-pins|clear-pin <service>]"


def main(argv: list[str]) -> int:
    if argv == ["list-pins"]:
        for service, digest in sorted(store.list_all(DB_PATH).items()):
            print(f"{service}\t{digest}")
        return 0
    if len(argv) == 2 and argv[0] == "clear-pin":
        service = argv[1]
        if store.clear(service, DB_PATH):
            print(f"cleared pin for {service!r}")
            return 0
        print(f"no pin found for {service!r}")
        return 1
    print(_USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
