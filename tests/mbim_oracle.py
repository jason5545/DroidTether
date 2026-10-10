#!/usr/bin/env python3
"""Cross-check DroidTether's MBIM messages against libmbim (the library ModemManager uses).

Runs on a Linux host with libmbim-glib installed (no modem needed, nothing is sent anywhere):

  build/test_mbim --dump > mbim.dump          # on the Mac
  python3 tests/mbim_oracle.py mbim.dump      # on the Linux host

For every request DroidTether builds, libmbim builds the same request with the same transaction id
and the bytes must match. Every response fixture in the dump is parsed by libmbim, and the fields
it reads must match what the test expects.
"""

import ctypes as C
import sys

lib = C.CDLL("libmbim-glib.so.4")
P = C.c_void_p
U32 = C.c_uint32
ERR = C.c_void_p  # GError ** (we pass None)


def fn(name, res, *args):
    f = getattr(lib, name)
    f.restype = res
    f.argtypes = list(args)
    return f


get_raw = fn("mbim_message_get_raw", C.POINTER(C.c_uint8), P, C.POINTER(U32), ERR)
set_tid = fn("mbim_message_set_transaction_id", None, P, U32)
msg_new = fn("mbim_message_new", P, C.c_char_p, U32)
printable = fn("mbim_message_get_printable", C.c_char_p, P, C.c_char_p, C.c_int)
uuid_ctx = fn("mbim_uuid_from_context_type", P, C.c_int)
CTX_INTERNET = uuid_ctx(2)  # MBIM_CONTEXT_TYPE_INTERNET

builders = {
    "open": lambda t: fn("mbim_message_open_new", P, U32, U32)(t, 4096),
    "close": lambda t: fn("mbim_message_close_new", P, U32)(t),
    "subscriber_ready_query": lambda t: fn("mbim_message_subscriber_ready_status_query_new", P, ERR)(None),
    "radio_query": lambda t: fn("mbim_message_radio_state_query_new", P, ERR)(None),
    "radio_set_on": lambda t: fn("mbim_message_radio_state_set_new", P, U32, ERR)(1, None),
    "register_query": lambda t: fn("mbim_message_register_state_query_new", P, ERR)(None),
    "packet_service_query": lambda t: fn("mbim_message_packet_service_query_new", P, ERR)(None),
    "packet_service_attach": lambda t: fn("mbim_message_packet_service_set_new", P, U32, ERR)(0, None),
    "connect_query": lambda t: fn("mbim_message_connect_query_new", P, U32, U32, U32, U32, P, U32, ERR)(
        0, 0, 0, 0, CTX_INTERNET, 0, None),
}


def connect_set(activate, apn, ip_type=1):
    f = fn("mbim_message_connect_set_new", P, U32, U32, C.c_char_p, C.c_char_p, C.c_char_p, U32, U32, U32, P, ERR)
    return lambda t: f(0, 1 if activate else 0, apn.encode() if apn else None, None, None, 0, 0, ip_type, CTX_INTERNET, None)


def pin_enter(pin):
    f = fn("mbim_message_pin_set_new", P, U32, U32, C.c_char_p, C.c_char_p, ERR)
    return lambda t: f(2, 0, pin.encode(), None, None)  # MBIM_PIN_TYPE_PIN1, MBIM_PIN_OPERATION_ENTER


builders["connect_activate_internet"] = connect_set(True, "internet")
builders["connect_deactivate"] = connect_set(False, "")
builders["connect_activate_a"] = connect_set(True, "a")
builders["connect_activate_fet"] = connect_set(True, "fet")
builders["connect_activate_internet_v4v6"] = connect_set(True, "internet", 3)
builders["pin_query"] = lambda t: fn("mbim_message_pin_query_new", P, ERR)(None)
builders["pin_enter_1234"] = pin_enter("1234")
builders["pin_enter_12345"] = pin_enter("12345")
builders["signal_query"] = lambda t: fn("mbim_message_signal_state_query_new", P, ERR)(None)
builders["device_caps_query"] = lambda t: fn("mbim_message_device_caps_query_new", P, ERR)(None)

# Response fixtures: the fields libmbim must read from them.
expect = {
    "real_ipcfg_done": ["IPv4ConfigurationAvailable = 'address, gateway, dns, mtu'", "OnLinkPrefixLength = '29'",
                        "IPv4Address = '100.98.240.100'", "IPv4Gateway = '100.98.240.101'",
                        "IPv4DnsServer = '61.31.1.1, 61.31.233.1'", "IPv4Mtu = '1500'"],
    "real_radio_done": ["HwRadioState = 'on'", "SwRadioState = 'on'"],
    "connect_done": ["SessionId = '0'", "ActivationState = 'activated'", "IpType = 'ipv4'",
                     "ContextType = '7e5e2a7e-4e6f-7272-736b-656e7e5e2a7e'", "NwError = '0'"],
    "connect_indication_deactivated": ["ActivationState = 'deactivated'", "NwError = '36'"],
    "register_done_home": ["NwError = 'none'", "RegisterState = 'home'"],
    "packet_service_done_attached": ["PacketServiceState = 'attached'"],
    "subscriber_ready_done": ["ReadyState = 'initialized'"],
    "pin_done_locked": ["PinType = 'pin1'", "PinState = 'locked'", "RemainingAttempts = '3'"],
    "signal_done": ["Rssi = '14'", "ErrorRate = '99'"],
    "register_done_named": ["ProviderId = '46697'", "ProviderName = 'TW Mobile'", "RegisterState = 'home'"],
    "ipcfg6_done": ["OnLinkPrefixLength = '30'", "IPv4Address = '10.21.162.178'", "IPv4Gateway = '10.21.162.177'",
                    "OnLinkPrefixLength = '64'", "IPv6Address = '2402:7500:4f6:9a73:8c45:3f2d:7a2f:ed8'",
                    "IPv6Gateway = '2402:7500:4f6:9a73:e965:6ce9:6ebc:bf6d'",
                    "IPv6DnsServer = '2001:4860:4860::8888, 2001:4860:4860::8844'", "IPv6Mtu = '1500'"],
    "device_caps_done": ["CustomDataClass = '5G/TDS'"],
}


def raw(m):
    n = U32()
    p = get_raw(m, C.byref(n), None)
    return bytes(p[: n.value])


def main(path):
    fails = 0
    for line in open(path):
        parts = line.split()
        if len(parts) != 3:
            continue
        kind, name, hexdata = parts
        ours = bytes.fromhex(hexdata)
        if kind == "req":
            tid = int.from_bytes(ours[8:12], "little")
            m = builders[name](tid)
            set_tid(m, tid)
            theirs = raw(m)
            ok = theirs == ours
            print(f"{'PASS' if ok else 'FAIL'}  request {name} ({len(ours)} bytes) matches libmbim")
            if not ok:
                print("   ours  ", ours.hex())
                print("   libmbim", theirs.hex())
                fails += 1
        elif kind == "resp":
            m = msg_new(ours, len(ours))
            text = printable(m, b"", 0).decode()
            missing = [e for e in expect[name] if e.replace(" ", "") not in text.replace(" ", "")]
            print(f"{'PASS' if not missing else 'FAIL'}  libmbim reads fixture {name} as expected")
            if missing:
                print("   missing:", missing)
                print("\n".join("   " + l for l in text.splitlines()))
                fails += 1
    print(f"\n{'all passed' if not fails else str(fails) + ' failed'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
