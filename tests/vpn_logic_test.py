#!/usr/bin/env python3
"""DroidTether VPN logic test: a full-tunnel VPN layered on the tether keeps its traffic.

With "main connection" on, the tether registers with OverridePrimary. A full-tunnel VPN
(here a Tailscale exit node) still has to win the default route, otherwise its traffic
leaves through the phone in the clear. Needs the installed daemon, a connected phone and
Tailscale online with at least one exit node available; no root.

  python3 tests/vpn_logic_test.py                  # picks an online exit node that is not Mullvad
  python3 tests/vpn_logic_test.py --exit-node NAME

Checked with the exit node on, both when it comes up after the tether and when the tether
connects while it is already on:
  1. configd's primary service is not DroidTether
  2. the route to 1.1.1.1 goes out the VPN interface, not the tether
  3. no 0/1 or 128/1 route points at the tether interface
  4. the public egress address is the exit node's, not the phone's
Then, with the exit node off again, the tether is primary and egress is the phone's again.
"""

import json
import re
import sys
import time

from dns_logic_test import (TAILSCALE, check, daemon, invariants, primary_service, route_iface, run, scenario,
                            status, summary, wait_connected, wait_until)
import dns_logic_test

EGRESS_URL = "https://api.ipify.org"


def ts_status():
    return json.loads(run(TAILSCALE, "status", "--json", timeout=10))


def current_exit_node(d):
    """The active exit node's Tailscale IPv4, or "" for none."""
    s = d.get("ExitNodeStatus")
    if not s:
        return ""
    return next((ip.split("/")[0] for ip in s.get("TailscaleIPs", []) if "." in ip), "")


def pick_exit_node(d, wanted):
    peers = [p for p in d.get("Peer", {}).values() if p.get("ExitNodeOption")]
    if wanted:
        p = next((p for p in peers if wanted in (p.get("HostName"), p.get("DNSName", "").split(".")[0])), None)
    else:
        # 自己的節點優先：Mullvad 的節點 DNSName 帶 mullvad.ts.net
        p = next((p for p in peers if p.get("Online") and "mullvad" not in p.get("DNSName", "")), None)
    if not p:
        return None, None
    return p.get("HostName"), next(ip for ip in p["TailscaleIPs"] if "." in ip)


def set_exit_node(ip):
    run(TAILSCALE, "set", f"--exit-node={ip}", timeout=20)
    return bool(wait_until(lambda: current_exit_node(ts_status()) == ip, 20, 0.5))


def egress():
    return run("/usr/bin/curl", "-4", "-s", "-m", "8", EGRESS_URL, timeout=12).strip()


def split_routes_on(iface):
    out = run("/usr/sbin/netstat", "-rn", "-f", "inet")
    return [l.split()[0] for l in out.splitlines()
            if l.split() and l.split()[0] in ("0/1", "128.0/1") and l.split()[-1] == iface]


def vpn_keeps_traffic(label, tether_iface, tether_egress, exit_name):
    ps = wait_until(lambda: (lambda p: p if p and p != "DroidTether" else None)(primary_service()), 15, 0.5)
    check(f"{label}: primary service is the VPN, not DroidTether", bool(ps), f"got {primary_service()}")
    time.sleep(4)  # daemon 最多等 3 秒看 configd 會不會把預設路由移過來
    ri = route_iface("1.1.1.1")
    check(f"{label}: route to 1.1.1.1 via the VPN", bool(ri) and ri.startswith("utun") and ri != tether_iface,
          f"got {ri}")
    split = split_routes_on(tether_iface)
    check(f"{label}: no 0/1, 128/1 routes on {tether_iface}", not split, f"found {split}")
    e = egress()
    check(f"{label}: egress through {exit_name}, not the phone", bool(e) and e != tether_egress,
          f"{e or 'no answer'} (phone: {tether_egress})")


def main():
    wanted = sys.argv[sys.argv.index("--exit-node") + 1] if "--exit-node" in sys.argv else None
    st = status()
    if not st:
        print("daemon not reachable")
        return 2
    try:
        d = ts_status()
    except Exception:
        print("Tailscale not reachable")
        return 2
    if not d["Self"].get("Online"):
        print("Tailscale is not online")
        return 2
    name, ip = pick_exit_node(d, wanted)
    if not ip:
        print("no usable exit node" + (f" named {wanted}" if wanted else ""))
        return 2
    original_exit = current_exit_node(d)
    original_primary = st["config"]["primary"]
    dns_logic_test.TS_EXPECTED = True

    try:
        scenario("baseline, no exit node")
        if original_exit:
            set_exit_node("")
        if not original_primary:
            daemon("set primary 1")
        st = wait_connected()
        if not check("connected and primary", st is not None):
            return summary()
        iface = st["interface"]
        tether_egress = egress()
        check("phone egress address known", bool(tether_egress), tether_egress)

        scenario(f"exit node {name} turned on while tethered")
        check("exit node on", set_exit_node(ip))
        vpn_keeps_traffic("exit node after tether", iface, tether_egress, name)

        scenario("tether reconnects while the exit node is on")
        since = status()["since"]
        daemon("reconnect")
        st = wait_until(lambda: (lambda s: s if s and s["state"] == "connected" and s["since"] != since else None)(
            status()), 40, 0.5)
        check("reconnected", st is not None)
        if st:
            iface = st["interface"]
            vpn_keeps_traffic("tether after exit node", iface, tether_egress, name)

        scenario("exit node off again")
        check("exit node off", set_exit_node(""))
        check("tether is primary again", wait_connected() is not None, f"got {primary_service()}")
        e = egress()
        check("egress through the phone again", e == tether_egress, f"{e} (phone: {tether_egress})")
        invariants("exit node off")
    finally:
        if current_exit_node(ts_status()) != original_exit:
            set_exit_node(original_exit)
        if not original_primary:
            daemon("set primary 0")

    return summary()


if __name__ == "__main__":
    sys.exit(main())
