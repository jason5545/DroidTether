#!/usr/bin/env python3
"""DroidTether DNS / routing logic test.

Proves, on a live system with the phone tethered, that the failure modes of
DNS-only tethering tools cannot happen here. Needs the installed daemon
(control socket) and a connected phone; no root.

  python3 tests/dns_logic_test.py           # full run (connection drops for a few seconds a few times)
  python3 tests/dns_logic_test.py --quick   # invariants only, no disruption

Invariants checked after every scenario:
  1. configd's primary service is DroidTether (when "main connection" is on)
  2. the default resolver is exactly the DNS list the daemon reports
  3. the route to each DNS server goes out the tether interface
  4. an uncached lookup (random name on a wildcard DNS service) resolves
  5. HTTPS works and leaves from the tether address
  6. Tailscale stays online and MagicDNS resolves (if Tailscale was online at start)
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


def default_resolver():
    """Nameservers mDNSResponder uses for ordinary names: first resolver with no domain that isn't supplemental."""
    main = run("/usr/sbin/scutil", "--dns").split("DNS configuration (for scoped queries)")[0]
    for block in re.split(r"\nresolver #\d+\n", main)[1:]:
        if re.search(r"^\s*domain\s*:", block, re.M):
            continue
        flags = re.search(r"flags\s*:\s*(.*)", block)
        if flags and "Supplemental" in flags.group(1):
            continue
        ns = re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", block)
        if ns:
            return ns
    return []


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


def wifi_up():
    return bool(run("/usr/sbin/ipconfig", "getifaddr", "en0").strip())


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
        dr = default_resolver()
        check(f"{label}: default resolver = daemon DNS", dr == dns, f"resolver {dr}, daemon {dns}")
    for d in dns:
        ri = route_iface(d)
        check(f"{label}: route to DNS {d} via {iface}", ri == iface, f"got {ri}")
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
    check("our IPv4+DNS entry is the default resolver", default_resolver() == status()["dns"],
          f"{default_resolver()}")
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
            check("no Wi-Fi: default resolver = daemon DNS", bool(s) and default_resolver() == s["dns"],
                  f"{default_resolver()}")
        invariants("secondary")
        daemon("set primary 1")
        check("main connection again", wait_connected() is not None)
        invariants("primary again")

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


def summary():
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
