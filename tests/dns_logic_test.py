#!/usr/bin/env python3
"""DroidTether DNS / routing logic test.

Proves, on a live system with the phone tethered, that the failure modes of
DNS-only tethering tools cannot happen here. Needs the installed daemon
(control socket) and a connected phone; no root.

  python3 tests/dns_logic_test.py           # full run (connection drops for a few seconds a few times)
  python3 tests/dns_logic_test.py --quick   # invariants only, no disruption

Invariants checked after every scenario:
  1. configd's primary service is DroidTether (when "main connection" is on)
  2. the default resolver is exactly the DNS list the daemon reports; if a domain-less resolver
     with a lower order sits in front of it (Tailscale with "Use Tailscale DNS" on), the check
     names it, since mDNSResponder then sends ordinary names there first
  3. the route to each DNS server goes out the tether interface
  4. each of those DNS servers answers an uncached name when asked directly with dig
     (bypasses mDNSResponder and Tailscale, so this is the check that the phone answers DNS)
  5. an uncached lookup (random name on a wildcard DNS service) resolves through the system
  6. HTTPS works and leaves from the tether address
  7. Tailscale stays online and MagicDNS resolves (if Tailscale was online at start)

The full run also covers "turn off Wi-Fi while connected" when Wi-Fi is on at the start
(Wi-Fi is switched off and on a few times).
"""

import concurrent.futures
import json
import random
import re
import socket
import subprocess
import sys
import time
import uuid

SOCK = "/var/run/droidtetherd.sock"
TAILSCALE = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
NETWORKSETUP = "/usr/sbin/networksetup"

passed = failed = 0


def check(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
    else:
        failed += 1
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)
    return ok


# ---------- 工具 ----------

def daemon(cmd, timeout=5):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(SOCK)
    s.sendall((cmd + "\n").encode())
    data = b""
    while not data.endswith(b"\n"):
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    return json.loads(data) if data.strip() else None


def status():
    try:
        return daemon("status")
    except (OSError, ValueError):
        return None


def run(*args, inp=None, timeout=15):
    return subprocess.run(args, input=inp, capture_output=True, text=True, timeout=timeout).stdout


def primary_service():
    m = re.search(r"PrimaryService : (\S+)", run("/usr/sbin/scutil", inp="show State:/Network/Global/IPv4\n"))
    return m.group(1) if m else None


def droidtether_keys():
    out = run("/usr/sbin/scutil", inp="list State:/Network/Service/DroidTether/.*\n")
    return re.findall(r"= (State:\S+)", out)


def resolvers():
    """Unscoped resolvers from `scutil --dns`, in listed order."""
    main = run("/usr/sbin/scutil", "--dns").split("DNS configuration (for scoped queries)")[0]
    out = []
    for block in re.split(r"\nresolver #\d+\n", main)[1:]:
        flags = re.search(r"flags\s*:\s*(.*)", block)
        order = re.search(r"order\s*:\s*(\d+)", block)
        iface = re.search(r"if_index\s*:\s*\d+\s*\((\S+)\)", block)
        out.append({
            "domain": bool(re.search(r"^\s*domain\s*:", block, re.M)),
            "supplemental": bool(flags and "Supplemental" in flags.group(1)),
            "order": int(order.group(1)) if order else None,
            "iface": iface.group(1) if iface else None,
            "ns": re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", block),
        })
    return out


def system_resolver(rs):
    """The resolver configd builds from the primary service: first one with no domain that isn't supplemental."""
    return next((r for r in rs if not r["domain"] and not r["supplemental"] and r["ns"]), None)


def default_resolver():
    r = system_resolver(resolvers())
    return r["ns"] if r else []


def resolvers_in_front():
    """Domain-less resolvers with a lower order than the system one. mDNSResponder sends ordinary names to them
    first even though scutil flags them Supplemental: Tailscale's 100.100.100.100 with "Use Tailscale DNS" on
    and tailnet global nameservers (mDNSResponder logs it with domain "." at order 100200, ours at 200000)."""
    rs = resolvers()
    ours = system_resolver(rs)
    if not ours or ours["order"] is None:
        return []
    names = []
    for r in rs:
        if r is ours or r["domain"] or not r["ns"] or r["order"] is None or r["order"] >= ours["order"]:
            continue
        who = "Tailscale" if "100.100.100.100" in r["ns"] else (r["iface"] or "another resolver")
        names.append(f"{who} {r['ns'][0]}")
    return names


def check_default_resolver(label, dns):
    """Invariant 2. Strict when nothing sits in front of our resolver. When something does, say what, so a pass
    never claims ordinary names go to the daemon's DNS while mDNSResponder actually asks Tailscale first."""
    dr, front = default_resolver(), resolvers_in_front()
    if front:
        name = f"DNS goes through {', '.join(front)} first, not daemon DNS; the system resolver behind it = daemon DNS"
    else:
        name = "default resolver = daemon DNS"
    return check(f"{label}: {name}", dr == dns, f"resolver {dr}, daemon {dns}")


def all_resolver_text():
    return run("/usr/sbin/scutil", "--dns")


def route_iface(ip):
    m = re.search(r"interface: (\S+)", run("/sbin/route", "-n", "get", "-inet", ip))
    return m.group(1) if m else None


_pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)


def resolve(name, timeout=4):
    fut = _pool.submit(socket.getaddrinfo, name, 443, socket.AF_INET)
    try:
        return fut.result(timeout=timeout)[0][4][0]
    except Exception:
        return None


def uncached_lookup():
    """A random name on a wildcard DNS service can't come from any cache, so it proves a resolver answered just now."""
    for svc in ("sslip.io", "nip.io"):
        n = random.randint(1, 254)
        name = f"dt-{uuid.uuid4().hex[:12]}.192-0-2-{n}.{svc}"
        t = time.time()
        ip = resolve(name)
        if ip == f"192.0.2.{n}":
            return True, f"{svc} {int((time.time() - t) * 1000)} ms"
    return False, "no answer from sslip.io or nip.io"


def direct_lookup(server):
    """Same random wildcard name, asked straight at one server with dig: bypasses mDNSResponder (and Tailscale
    in front of it), so a pass means that server itself answered over the tether."""
    errors = []
    for svc in ("sslip.io", "nip.io"):
        n = random.randint(1, 254)
        name = f"dt-{uuid.uuid4().hex[:12]}.192-0-2-{n}.{svc}"
        t = time.time()
        out = run("/usr/bin/dig", f"@{server}", name, "A", "+time=3", "+tries=1")
        ms = int((time.time() - t) * 1000)
        answers = re.findall(r"\sIN\s+A\s+(\d+\.\d+\.\d+\.\d+)", out)
        if f"192.0.2.{n}" in answers:
            return True, f"{svc} {ms} ms"
        if "timed out" in out or "no servers could be reached" in out:
            errors.append(f"{svc}: no reply in 3 s")
        else:
            m = re.search(r"status: (\w+)", out)
            errors.append(f"{svc}: {m.group(1) if m else 'no response'}, answer {answers or 'empty'}")
    return False, "; ".join(errors)


def wifi_up():
    return bool(run("/usr/sbin/ipconfig", "getifaddr", "en0").strip())


def wifi_power():
    return run(NETWORKSETUP, "-getairportpower", "en0").strip().rsplit(" ", 1)[-1]


def set_wifi_power(on):
    run(NETWORKSETUP, "-setairportpower", "en0", "on" if on else "off")


def https(interface=None):
    args = ["/usr/bin/curl", "-4", "-m", "8", "-s", "-o", "/dev/null", "-w", "%{http_code} %{local_ip}"]
    if interface:
        args += ["--interface", interface]
    out = run(*args, "https://www.google.com/generate_204", timeout=12).split()
    return (out[0], out[1]) if len(out) == 2 else ("000", "")


def tailscale_state():
    try:
        d = json.loads(run(TAILSCALE, "status", "--json", timeout=10))
        return d["Self"].get("Online", False), d["Self"].get("DNSName", "").rstrip(".")
    except Exception:
        return None, None


def wait_until(pred, timeout, interval=0.3):
    end = time.time() + timeout
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(interval)
    return pred()


def wait_connected(timeout=30):
    def ready():
        s = status()
        if not s or s.get("state") != "connected":
            return None
        if s["config"]["primary"] and primary_service() != "DroidTether":
            return None
        return s
    s = wait_until(ready, timeout)
    time.sleep(1.5)  # 給 mDNSResponder 一點時間吃進新設定
    return status() if s else None


# ---------- 不變式 ----------

TS_EXPECTED = False


def invariants(label):
    st = status()
    if not check(f"{label}: daemon connected", st is not None and st.get("state") == "connected",
                 st.get("state") if st else "no reply"):
        return
    iface, dns, primary = st["interface"], st["dns"], st["config"]["primary"]
    if primary:
        ps = primary_service()
        check(f"{label}: primary service is DroidTether", ps == "DroidTether", f"got {ps}")
        check_default_resolver(label, dns)
    who = "the phone" if st["config"]["dns_mode"] == "phone" else "the custom DNS server"
    for d in dns:
        ri = route_iface(d)
        check(f"{label}: route to DNS {d} via {iface}", ri == iface, f"got {ri}")
        ok, detail = direct_lookup(d)
        check(f"{label}: DNS {d} answers when asked directly (dig, no mDNSResponder/Tailscale)", ok,
              detail if ok else f"{who} ({d}) did not answer DNS over the tether: {detail}")
    ok, detail = uncached_lookup()
    check(f"{label}: uncached lookup resolves", ok, detail)
    code, local = https(None if primary else iface)
    check(f"{label}: HTTPS from tether address", code == "204" and local == st["ip"], f"{code} from {local}")
    if TS_EXPECTED:
        online = wait_until(lambda: tailscale_state()[0], 20, 1)
        check(f"{label}: Tailscale online", bool(online))
        _, me = tailscale_state()
        ip = resolve(me) if me else None
        check(f"{label}: MagicDNS resolves {me}", bool(ip) and ip.startswith("100."), f"got {ip}")


# ---------- 情境 ----------

def scenario(title):
    print(f"\n== {title}", flush=True)


def main():
    global TS_EXPECTED
    quick = "--quick" in sys.argv
    st = status()
    if not st:
        print("daemon not reachable on", SOCK)
        return 2
    original = st["config"]
    ts_online, _ = tailscale_state()
    TS_EXPECTED = bool(ts_online)

    scenario("baseline")
    if not wait_connected(20):
        print("phone is not connected; enable USB tethering first")
        return 2
    invariants("baseline")

    scenario("A/B: the DNS-only write that MacTethering-style tools use")
    check("legacy write accepted", (daemon("debug legacy-dns 9.9.9.9") or {}).get("ok") is True)
    time.sleep(2)
    text = all_resolver_text()
    check("configd ignores a DNS entry without IPv4 (9.9.9.9 never reaches the resolver)", "9.9.9.9" not in text)
    check_default_resolver("our IPv4+DNS entry still in use", status()["dns"])
    daemon("debug legacy-dns-clear")

    if quick:
        return summary()

    try:
        scenario("reconnect")
        daemon("reconnect")
        check("reconnected", wait_connected() is not None)
        invariants("after reconnect")

        scenario("pause and resume")
        daemon("set enabled 0")
        check("paused", bool(wait_until(lambda: (status() or {}).get("state") == "disabled", 10)))
        gone = wait_until(lambda: not droidtether_keys(), 5)
        check("no DroidTether entries left in configd", bool(gone), str(droidtether_keys()))
        check("primary moved off DroidTether", primary_service() != "DroidTether", f"got {primary_service()}")
        if wifi_up():
            ok, detail = uncached_lookup()
            check("DNS still works over Wi-Fi while paused", ok, detail)
        daemon("set enabled 1")
        check("resumed", wait_connected() is not None)
        invariants("after resume")

        scenario("custom DNS, then back to the phone's DNS")
        daemon("set dns 1.1.1.1,8.8.8.8")
        s = wait_connected()
        check("custom DNS applied", s is not None and s["dns"] == ["1.1.1.1", "8.8.8.8"], str(s and s["dns"]))
        invariants("custom DNS")
        daemon("set dns phone")
        check("phone DNS applied", wait_connected() is not None)
        invariants("phone DNS")

        if "dns_fallback" in (status() or {}):
            dns_fallback_scenario()

        scenario("not the main connection")
        daemon("set primary 0")
        s = wait_connected()
        check("still connected", s is not None)
        if wifi_up():
            check("Wi-Fi stays primary", primary_service() != "DroidTether", f"got {primary_service()}")
            check("tether DNS is not the default resolver", s is not None and default_resolver() != s["dns"],
                  f"{default_resolver()}")
        else:
            # 沒有別的網路時，不搶主要連線也一樣要能用：系統自己會選手機，DNS 也要跟著過去
            s = wait_until(lambda: primary_service() == "DroidTether" and status(), 15)
            check("no Wi-Fi: macOS still picks the tether on its own", bool(s), f"got {primary_service()}")
            check_default_resolver("no Wi-Fi", s["dns"] if s else None)
        invariants("secondary")
        daemon("set primary 1")
        check("main connection again", wait_connected() is not None)
        invariants("primary again")

        if "wifi_off" in original and wifi_power() == "On":
            wifi_scenario()

        scenario("configd loses our entries (e.g. configd restart)")
        pid = run("/usr/bin/pgrep", "-x", "droidtetherd").split()
        daemon("debug drop-netcfg")
        check("entries really removed", not droidtether_keys() or primary_service() != "DroidTether")
        healed = wait_until(lambda: droidtether_keys() and primary_service() == "DroidTether", 12, 0.5)
        check("daemon re-registers them within 12 s", bool(healed))
        # 當掉被 launchd 重啟也會「恢復」，那不算：同一個行程自己補回來才算
        check("same daemon process did it (no crash/restart)", run("/usr/bin/pgrep", "-x", "droidtetherd").split() == pid,
              f"pid {pid} -> {run('/usr/bin/pgrep', '-x', 'droidtetherd').split()}")
        time.sleep(1.5)
        invariants("after self-heal")

        scenario("daemon crash")
        before = run("/usr/bin/pgrep", "-x", "droidtetherd").split()
        try:
            daemon("debug abort", timeout=2)
        except (OSError, ValueError):
            pass
        saw_clean = wait_until(lambda: not droidtether_keys(), 5, 0.1)
        check("configd drops our entries when the process dies", bool(saw_clean))
        s = wait_connected(40)
        after = run("/usr/bin/pgrep", "-x", "droidtetherd").split()
        check("launchd restarted the daemon and it reconnected", s is not None and after and after != before,
              f"pid {before} -> {after}")
        ifaces = run("/sbin/ifconfig", "-l").split()
        feths = sorted(i for i in ifaces if i.startswith("feth"))
        check("no leftover interfaces", feths == ["feth7700", "feth7701"], " ".join(feths))
        invariants("after crash")
    finally:
        cfg = status()
        if cfg and "wifi_off" in original and cfg["config"].get("wifi_off") != original["wifi_off"]:
            daemon(f"set wifi_off {1 if original['wifi_off'] else 0}")
        if "wifi_off" in original and wifi_power() != "On":
            set_wifi_power(True)
        if cfg:
            if not original["enabled"]:
                daemon("set enabled 0")
            if original["dns_mode"] == "custom":
                daemon("set dns " + ",".join(original["dns_servers"]))
            elif cfg["config"]["dns_mode"] != "phone":
                daemon("set dns phone")
            if cfg["config"]["primary"] != original["primary"]:
                daemon(f"set primary {1 if original['primary'] else 0}")

    return summary()


def unused_tether_address(st):
    """An address on the tether subnet that neither the Mac nor the phone uses: nothing will answer there."""
    ip = [int(x) for x in st["ip"].split(".")]
    mask = [int(x) for x in st["netmask"].split(".")]
    net = [a & m for a, m in zip(ip, mask)]
    for host in range(1, 255):
        cand = ".".join(map(str, net[:3] + [net[3] + host]))
        if cand not in (st["ip"], st["gateway"]):
            return cand
    return None


def dns_fallback_scenario():
    scenario("phone does not answer DNS (simulated)")
    st = status()
    phone = st["dns"]
    r = daemon(f"debug dns-probe {phone[0]}") or {}
    check(f"probe: the phone answers DNS at {phone[0]}", r.get("answered") is True, str(r))
    unused = unused_tether_address(st)
    r = daemon(f"debug dns-probe {unused}", timeout=6) or {}
    check(f"probe: nothing answers at {unused}", r.get("answered") is False, str(r))

    daemon("debug dns-probe-fail 1")
    since = None
    try:
        daemon("reconnect")
        s = wait_connected()
        check("reconnected", s is not None)
        check("falls back to 8.8.8.8, 8.8.4.4", bool(s) and s.get("dns") == ["8.8.8.8", "8.8.4.4"]
              and s.get("dns_fallback") is True, str(s and (s.get("dns"), s.get("dns_fallback"))))
        invariants("fallback DNS")
        since = (status() or {}).get("since")
    finally:
        daemon("debug dns-probe-fail 0")
    t0 = time.time()
    back = wait_until(lambda: (lambda x: bool(x) and x.get("dns") == phone and x.get("dns_fallback") is False)(status()),
                      75, 1)
    check("switches back to the phone's DNS once it answers", bool(back),
          f"{time.time() - t0:.0f} s, dns {(status() or {}).get('dns')}")
    check("without reconnecting", (status() or {}).get("since") == since)
    time.sleep(1.5)
    invariants("phone DNS again")


def pause_and_wait():
    daemon("set enabled 0")
    return bool(wait_until(lambda: (status() or {}).get("state") == "disabled", 10))


def wifi_scenario():
    def power_is(v, timeout=10):
        return bool(wait_until(lambda: wifi_power() == v, timeout, 0.3))

    scenario("turn off Wi-Fi while connected")
    daemon("set wifi_off 1")
    check("Wi-Fi turned off without reconnecting", power_is("Off"))
    invariants("Wi-Fi off")

    # 暫停跟拔線走同一條路：撤掉網路服務、刪掉介面，主迴圈回報手機不在
    t0 = time.time()
    check("paused", pause_and_wait())
    check("Wi-Fi back on after the tether goes away", power_is("On"))
    ok = wait_until(lambda: wifi_up() and uncached_lookup()[0], 30, 0.5)
    check("DNS works over Wi-Fi again", bool(ok), f"{time.time() - t0:.1f} s after the tether went away")

    daemon("set enabled 1")
    check("reconnected", wait_connected() is not None)
    check("Wi-Fi off again on the next connection", power_is("Off"))

    set_wifi_power(True)
    time.sleep(7)  # 超過 daemon 每 5 秒一次的檢查
    check("Wi-Fi the user turns back on stays on", wifi_power() == "On")
    check("paused", pause_and_wait())
    set_wifi_power(False)
    daemon("set enabled 1")
    check("reconnected with Wi-Fi already off", wait_connected() is not None)
    check("paused", pause_and_wait())
    time.sleep(3)
    check("Wi-Fi that was already off stays off", wifi_power() == "Off")
    set_wifi_power(True)
    daemon("set enabled 1")
    check("reconnected", wait_connected() is not None)
    check("Wi-Fi off again", power_is("Off"))

    before = run("/usr/bin/pgrep", "-x", "droidtetherd").split()
    try:
        daemon("debug abort", timeout=2)
    except (OSError, ValueError):
        pass
    s = wait_connected(40)
    check("daemon restarted and reconnected", s is not None and run("/usr/bin/pgrep", "-x", "droidtetherd").split() != before)
    check("Wi-Fi still off after the crash", wifi_power() == "Off")
    check("paused", pause_and_wait())
    check("restarted daemon still turns Wi-Fi back on", power_is("On"))
    daemon("set enabled 1")
    s = wait_connected()
    check("reconnected", s is not None)
    check("Wi-Fi off again", power_is("Off"))

    since = (status() or {}).get("since")
    daemon("set wifi_off 0")
    check("turning the setting off brings Wi-Fi back", power_is("On"))
    check("without reconnecting", (status() or {}).get("since") == since and status()["state"] == "connected")
    invariants("setting off")


def summary():
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
