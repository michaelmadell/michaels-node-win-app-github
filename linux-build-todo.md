# Linux Network State Reporting — Fix List

The Linux and Windows builds share the same serial message format:
```
network, <macAddress>, <linkStatus>, <ipv4>, <ipv6>, <dhcp>, <name>
```
However, `LinuxPlatform::getNetworkInterfaces()` populates several fields differently from
the Windows implementation, causing the BMC to receive inconsistent or unexpected data.

---

## Fix 1 — CRITICAL: Add MAC address vendor filtering

File: `src/platform/LinuxPlatform.cpp`

Windows (`WindowsPlatform.cpp:403–405`) filters out any NIC whose MAC OUI does not match
a known Amulet Hotkey, AAEON, or Congatec prefix. Linux currently reports **all**
non-loopback interfaces. The BMC will receive NIC entries it does not recognise (USB-Ethernet
dongles, virtual bridges, etc.) and may misparse the state.

**Add the vendor filter after populating `macAddress` in `getNetworkInterfaces()`:**

```cpp
// After building interfaces_map and before pushing to result_vector,
// filter to known vendor OUIs only:
std::vector<NetworkInterface> result_vector;
for (auto const& [name, iface] : interfaces_map) {
    const std::string& mac = iface.macAddress;
    if (mac.compare(0, 8, "00:17:fd") == 0 || // Amulet Hotkey
        mac.compare(0, 8, "00:07:32") == 0 || // AAEON
        mac.compare(0, 8, "00:13:95") == 0)   // Congatec
    {
        result_vector.push_back(iface);
    }
}
return result_vector;
```

> Note: the OUI prefixes use lowercase to match the Linux hex formatting (see Fix 2).

---

## Fix 2 — CRITICAL: Normalise MAC address case to uppercase

File: `src/platform/LinuxPlatform.cpp`

Linux builds the MAC with `std::hex` and no `std::uppercase`, producing lowercase
(e.g. `00:17:fd:xx:xx:xx`). Windows uses `std::uppercase`, producing `00:17:FD:XX:XX:XX`.
If the BMC does a case-sensitive MAC comparison, Linux devices will always fail the lookup.

**Current (lines ~398–403):**
```cpp
std::stringstream ss;
for (int i = 0; i < s->sll_halen; i++) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)s->sll_addr[i];
    if (i < s->sll_halen - 1) ss << ":";
}
interfaces_map[name].macAddress = ss.str();
```

**New — add `std::uppercase`:**
```cpp
std::stringstream ss;
for (int i = 0; i < s->sll_halen; i++) {
    ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)s->sll_addr[i];
    if (i < s->sll_halen - 1) ss << ":";
}
interfaces_map[name].macAddress = ss.str();
```

> Also update Fix 1's OUI prefix strings to uppercase once this is applied:
> `"00:17:FD"`, `"00:07:32"`, `"00:13:95"`.

---

## Fix 3 — HIGH: Report real link status instead of hardcoded "up"

File: `src/platform/LinuxPlatform.cpp`

Linux hardcodes `interfaces_map[name].linkStatus = "up"` for all interfaces regardless of
actual carrier state. Windows reads `pAdapter->OperStatus` and sends `"up"` or `"down"`.
A NIC that is cabled but has no link will still report `"up"` on Linux.

**Current (line ~388):**
```cpp
interfaces_map[name].linkStatus = "up";
```

**New — read the carrier file from sysfs:**
```cpp
std::string carrierPath = "/sys/class/net/" + name + "/operstate";
std::ifstream carrierFile(carrierPath);
std::string operstate;
if (carrierFile >> operstate && operstate == "up") {
    interfaces_map[name].linkStatus = "up";
} else {
    interfaces_map[name].linkStatus = "down";
}
```

> `/sys/class/net/<iface>/operstate` returns `"up"`, `"down"`, `"unknown"`, etc.
> Treat anything other than `"up"` as `"down"` to match Windows behaviour.

---

## Fix 4 — MEDIUM: Verify `getDhcpStatus()` returns `"dhcp"` / `"static"` to match Windows

File: `src/platform/LinuxPlatform.cpp`

Windows returns the string `"dhcp"` or `"static"` based on the `IP_ADAPTER_DHCP_ENABLED`
flag. Linux delegates to `getDhcpStatus(name)`. Confirm the function returns exactly
`"dhcp"` or `"static"` (not `"yes"/"no"`, `"true"/"false"`, etc.) to keep the serial
message parseable by the BMC.

**Expected return values:**
```
"dhcp"    — interface is obtaining address via DHCP
"static"  — interface has a static address assignment
```

Review `getDhcpStatus()` and ensure it produces exactly these two strings. If it currently
returns a different value, normalise the output at the call site:

```cpp
std::string dhcpRaw = getDhcpStatus(name);
interfaces_map[name].dhcp = (dhcpRaw == "dhcp") ? "dhcp" : "static";
```

---

## Fix 5 — LOW: Skip link-local IPv6 consistently

File: `src/platform/LinuxPlatform.cpp`

Linux already skips addresses beginning with `fe80::` (line ~412). Windows iterates
`FirstUnicastAddress` and reports the first IPv6 found without filtering link-local
addresses. Both behaviours may differ on dual-stack systems. The Linux behaviour
(skip link-local, report only global unicast) is the correct one — no code change needed,
but verify Windows is consistent if that platform is ever revisited.

---

## Summary Table

| Priority | Fix | Change |
|----------|-----|--------|
| CRITICAL | Fix 1 | Add vendor OUI filter — Linux currently sends all NICs, BMC only expects known vendor MACs |
| CRITICAL | Fix 2 | Uppercase MAC hex — Linux sends lowercase, Windows sends uppercase; BMC lookup will fail |
| HIGH     | Fix 3 | Read real `operstate` from sysfs — Linux always sends `"up"` even for disconnected NICs |
| MEDIUM   | Fix 4 | Confirm `getDhcpStatus()` returns `"dhcp"` / `"static"` — mismatch breaks BMC parsing |
| LOW      | Fix 5 | No action required — Linux IPv6 link-local filtering is already correct |
