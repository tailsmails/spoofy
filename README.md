# Spoofy

A lightweight, zero-dependency, and highly robust CLI raw packet generator written in V. Designed specifically for network auditing, firewall rules validation, and testing BCP 38 compliance across both IPv4 and IPv6 networks.

## Features

* **Dual-Stack Support:** Native generation and handling of raw UDP packets across both IPv4 and IPv6 networks.
* **Source IP Spoofing:** Leverage `IP_HDRINCL` on IPv4 and advanced `IPV6_FREEBIND` socket binding on IPv6 to audit network path filters.
* **Hex Payload Parsing:** Out-of-the-box support for raw hex strings (e.g., `0x...`, `\x...`) to construct complex binary network payloads such as custom DNS Queries or NTP synchronization sequences.
* **Native OS Error Handling:** Direct translation of C-level kernel error codes (`errno`) to readable text, ensuring quick diagnostic of kernel blocks or permission limits.
* **Zero External Dependencies:** Built entirely with V's native flag parser and direct POSIX system bindings.

## Requirements

* **Linux-based OS:** Raw socket operations (`SOCK_RAW`) require POSIX socket environments.
* **Root Privileges:** Generating raw packets requires executing with administrator access (`sudo` or `CAP_NET_RAW` capability).

## Quick Install

Ensure you compile with native GCC to achieve the highest optimization and seamless low-level C interop on your machine:

```sh
apt update -y && apt install -y git clang make && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && ./v symlink && cd ..; fi && git clone --depth=1 https://github.com/tailsmails/spoofy && cd spoofy && v -prod spoofy.v -o spoofy && ln -sf $(pwd)/spoofy $PREFIX/bin/spoofy
```

## OS Configuration for Spoofing

Before performing audit tests with non-local source IPs, configure your local Linux kernel to allow binding to arbitrary spoofed IP addresses:

```sh
# For IPv4 auditing
sudo sysctl -w net.ipv4.ip_nonlocal_bind=1

# For IPv6 auditing
sudo sysctl -w net.ipv6.ip_nonlocal_bind=1
```

## Usage Examples

### IPv4 Loopback Auditing (Plain Text Payload)
```sh
sudo spoofy -t 127.0.0.1 -s 1.1.1.1 -p 53 -m "hello local audit" -c 1
```

### IPv6 Loopback Auditing (Hand-crafted DNS Query)
```sh
sudo spoofy -t ::1 -s 2001:db8::123 -p 53 -m "0x12340100000100000000000006676f6f676c6503636f6d0000010001" -c 1
```