module main

import os
import flag
import rand

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

fn C.socket(domain int, @type int, protocol int) int
fn C.close(fd int) int
fn C.setsockopt(fd int, level int, optname int, optval voidptr, optlen u32) int
fn C.bind(fd int, addr voidptr, addrlen u32) int
fn C.sendto(fd int, buf voidptr, len usize, flags int, dest_addr voidptr, addrlen u32) isize
fn C.inet_pton(af int, src &u8, dst voidptr) int

const af_inet        = 2
const af_inet6       = 10
const ipproto_ip     = 0
const ipproto_ipv6   = 41
const ip_hdrincl     = 2
const ipv6_freebind  = 78

struct SockAddrIn6 {
mut:
	sin6_family   u16
	sin6_port     u16
	sin6_flowinfo u32
	sin6_addr     [16]u8
	sin6_scope_id u32
}

fn v_htons(val u16) u16 {
	$if little_endian {
		return (val >> 8) | (val << 8)
	} $else {
		return val
	}
}

fn get_errno_msg(err int) string {
	return match err {
		1 { 'Operation not permitted' }
		13 { 'Permission denied (Run with sudo)' }
		98 { 'Address already in use' }
		99 { 'Cannot assign requested address (Non-local IP binding is disabled by kernel)' }
		else { 'System error code: ${err}' }
	}
}

fn ip_checksum(buf []u8) u16 {
	mut sum := u32(0)
	mut i := 0
	for i + 1 < buf.len {
		sum += (u32(buf[i]) << 8) | u32(buf[i + 1])
		i += 2
	}
	if i < buf.len { sum += u32(buf[i]) << 8 }
	for (sum >> 16) != 0 { sum = (sum & 0xffff) + (sum >> 16) }
	mut ans := u16(~sum & 0xffff)
	if ans == 0 { ans = 0xffff }
	return ans
}

fn udp_checksum(src_ip []u8, dst_ip []u8, udp_packet []u8) u16 {
	mut sum := u32(0)
	sum += (u32(src_ip[0]) << 8) | u32(src_ip[1])
	sum += (u32(src_ip[2]) << 8) | u32(src_ip[3])
	sum += (u32(dst_ip[0]) << 8) | u32(dst_ip[1])
	sum += (u32(dst_ip[2]) << 8) | u32(dst_ip[3])
	sum += 0x0011
	sum += u32(udp_packet.len)
	mut i := 0
	for i + 1 < udp_packet.len {
		sum += (u32(udp_packet[i]) << 8) | u32(udp_packet[i + 1])
		i += 2
	}
	if i < udp_packet.len { sum += u32(udp_packet[i]) << 8 }
	for (sum >> 16) != 0 { sum = (sum & 0xffff) + (sum >> 16) }
	mut ans := u16(~sum & 0xffff)
	if ans == 0 { ans = 0xffff }
	return ans
}

fn build_raw_udp_v4(src_ip []u8, dst_ip []u8, src_port u16, dst_port u16, payload []u8) []u8 {
	udp_len := 8 + payload.len
	total_len := 20 + udp_len
	mut pkt := []u8{len: total_len}
	pkt[0] = 0x45
	pkt[1] = 0x00
	pkt[2] = u8((total_len >> 8) & 0xff)
	pkt[3] = u8(total_len & 0xff)
	pkt[4] = 0xDE
	pkt[5] = 0xAD
	pkt[6] = 0x40
	pkt[7] = 0x00
	pkt[8] = 64
	pkt[9] = 17

	for i in 0 .. 4 {
		pkt[12 + i] = src_ip[i]
		pkt[16 + i] = dst_ip[i]
	}

	ip_ck := ip_checksum(pkt[..20])
	pkt[10] = u8((ip_ck >> 8) & 0xff)
	pkt[11] = u8(ip_ck & 0xff)
	pkt[20] = u8((src_port >> 8) & 0xff)
	pkt[21] = u8(src_port & 0xff)
	pkt[22] = u8((dst_port >> 8) & 0xff)
	pkt[23] = u8(dst_port & 0xff)
	pkt[24] = u8((udp_len >> 8) & 0xff)
	pkt[25] = u8(udp_len & 0xff)
	pkt[26] = 0
	pkt[27] = 0

	for i in 0 .. payload.len { pkt[28 + i] = payload[i] }

	udp_ck := udp_checksum(src_ip, dst_ip, pkt[20..])
	pkt[26] = u8((udp_ck >> 8) & 0xff)
	pkt[27] = u8(udp_ck & 0xff)

	return pkt
}

fn build_udp_v6(src_port u16, dst_port u16, payload []u8) []u8 {
	udp_len := 8 + payload.len
	mut pkt := []u8{len: udp_len}
	pkt[0] = u8((src_port >> 8) & 0xff)
	pkt[1] = u8(src_port & 0xff)
	pkt[2] = u8((dst_port >> 8) & 0xff)
	pkt[3] = u8(dst_port & 0xff)
	pkt[4] = u8((udp_len >> 8) & 0xff)
	pkt[5] = u8(udp_len & 0xff)
	pkt[6] = 0
	pkt[7] = 0
	
	for i in 0 .. payload.len { pkt[8 + i] = payload[i] }
	return pkt
}

fn hex_val(ch u8) ?u8 {
	if ch >= `0` && ch <= `9` { return u8(ch - `0`) }
	if ch >= `a` && ch <= `f` { return u8(ch - `a` + 10) }
	if ch >= `A` && ch <= `F` { return u8(ch - `A` + 10) }
	return none
}

fn byte_from_hex(hex_pair string) ?u8 {
	if hex_pair.len != 2 { return none }
	h1 := hex_val(hex_pair[0])?
	h2 := hex_val(hex_pair[1])?
	return u8((h1 << 4) | h2)
}

fn parse_payload(msg string) []u8 {
	s := msg.trim_space()
	is_hex := s.starts_with('0x') || s.starts_with('\\x') || s.starts_with('hex:')
	
	if !is_hex {
		return s.bytes()
	}
	
	mut clean := s.replace('0x', '').replace('\\x', '').replace('hex:', '').replace(' ', '').replace(':', '')
	if clean.len % 2 != 0 {
		clean = '0' + clean
	}
	
	mut bytes := []u8{cap: clean.len / 2}
	for i := 0; i < clean.len; i += 2 {
		pair := clean[i..i+2]
		val := byte_from_hex(pair) or { 0 }
		bytes << val
	}
	return bytes
}

fn main() {
	$if !windows {
		if os.getuid() != 0 {
			eprintln('[\033[31m!\033[0m] Error: This tool requires root privileges (sudo).')
			exit(1)
		}
	}
	
	mut fp := flag.new_flag_parser(os.args)
	fp.application('spoofy')
	fp.version('1.1.1')
	fp.description('A robust raw packet CLI generator with IPv4/IPv6 dual-stack and advanced error reporting.')
	fp.skip_executable()

	target_ip_str := fp.string('target', `t`, '', 'Target IP address (IPv4 or IPv6)')
	spoof_ip_str := fp.string('spoof', `s`, '', 'Spoofed Source IP address (IPv4 or IPv6)')
	port := fp.int('port', `p`, 53, 'Destination Port (Default: 53)')
	message := fp.string('message', `m`, 'test payload', 'Message data or raw Hex to send')
	count := fp.int('count', `c`, 1, 'Number of packets to send')

	fp.finalize() or {
		println(fp.usage())
		return
	}

	if target_ip_str == '' || spoof_ip_str == '' {
		println(fp.usage())
		return
	}

	is_v6 := target_ip_str.contains(':')
	src_port := u16(rand.intn(50000) or { 10000 } + 10000)
	dst_port := u16(port)
	payload := parse_payload(message)

	println('[\033[36m~\033[0m] Diagnostic: Detecting IP family...')

	if !is_v6 {
		println('[\033[32m+\033[0m] IPv4 network family selected.')
		mut dst_ip := [4]u8{}
		mut src_ip := [4]u8{}
		if C.inet_pton(af_inet, target_ip_str.str, voidptr(&dst_ip[0])) <= 0 {
			eprintln('[\033[31m!\033[0m] Invalid target IPv4 address.')
			return
		}
		if C.inet_pton(af_inet, spoof_ip_str.str, voidptr(&src_ip[0])) <= 0 {
			eprintln('[\033[31m!\033[0m] Invalid spoof IPv4 address.')
			return
		}

		raw_pkt := build_raw_udp_v4(src_ip[..], dst_ip[..], src_port, dst_port, payload)

		$if !windows {
			raw_fd := C.socket(af_inet, C.SOCK_RAW, 255)
			if raw_fd < 0 {
				err_msg := get_errno_msg(C.errno)
				eprintln('[\033[31m!\033[0m] Failed to create raw IPv4 socket: ${err_msg}')
				return
			}
			mut one := int(1)
			if C.setsockopt(raw_fd, ipproto_ip, ip_hdrincl, &one, sizeof(one)) < 0 {
				err_msg := get_errno_msg(C.errno)
				eprintln('[\033[31m!\033[0m] setsockopt IP_HDRINCL failed: ${err_msg}')
			}

			mut dest := [16]u8{}
			dest[0] = u8(af_inet & 0xff)
			dest[1] = u8((af_inet >> 8) & 0xff)
			dest[2] = u8(dst_port >> 8)
			dest[3] = u8(dst_port & 0xff)
			for idx in 0 .. 4 { dest[4 + idx] = dst_ip[idx] }

			println('[\033[36m~\033[0m] Ready to fire ${count} packets:')
			println('    From (Spoofed): ${spoof_ip_str}:${src_port}')
			println('    To (Real Target): ${target_ip_str}:${dst_port}')

			for i in 0 .. count {
				sent := C.sendto(raw_fd, voidptr(raw_pkt.data), raw_pkt.len, 0, voidptr(&dest), u32(16))
				if sent < 0 {
					err_msg := get_errno_msg(C.errno)
					eprintln('[\033[31m!\033[0m] Failed to send IPv4 packet #${i + 1}: ${err_msg}')
				} else {
					println('[\033[32m+\033[0m] IPv4 Packet #${i + 1} sent successfully (${sent} bytes).')
				}
			}
			C.close(raw_fd)
		}
	} else {
		println('[\033[32m+\033[0m] IPv6 network family selected.')
		mut dst_ip := [16]u8{}
		mut src_ip := [16]u8{}
		if C.inet_pton(af_inet6, target_ip_str.str, voidptr(&dst_ip[0])) <= 0 {
			eprintln('[\033[31m!\033[0m] Invalid target IPv6 address.')
			return
		}
		if C.inet_pton(af_inet6, spoof_ip_str.str, voidptr(&src_ip[0])) <= 0 {
			eprintln('[\033[31m!\033[0m] Invalid spoof IPv6 address.')
			return
		}

		udp_pkt := build_udp_v6(src_port, dst_port, payload)

		$if !windows {
			raw_fd := C.socket(af_inet6, C.SOCK_RAW, 17)
			if raw_fd < 0 {
				err_msg := get_errno_msg(C.errno)
				eprintln('[\033[31m!\033[0m] Failed to create raw IPv6 socket: ${err_msg}')
				return
			}

			mut one := int(1)
			if C.setsockopt(raw_fd, ipproto_ipv6, ipv6_freebind, &one, sizeof(one)) < 0 {
				err_msg := get_errno_msg(C.errno)
				println('[\033[33m!\033[0m] Warning: IPV6_FREEBIND setsockopt failed (${err_msg}). Spoofing might require local interface binding.')
			}

			mut bind_addr := SockAddrIn6{
				sin6_family: u16(af_inet6)
				sin6_port: v_htons(src_port)
			}
			for idx in 0 .. 16 { bind_addr.sin6_addr[idx] = src_ip[idx] }

			if C.bind(raw_fd, &bind_addr, u32(sizeof(bind_addr))) < 0 {
				err_msg := get_errno_msg(C.errno)
				eprintln('[\033[31m!\033[0m] Bind failed to spoofed IPv6 source IP: ${err_msg}')
				println('[\033[36m*\033[0m] Try executing: sudo sysctl -w net.ipv6.ip_nonlocal_bind=1')
				C.close(raw_fd)
				return
			}

			mut dest := SockAddrIn6{
				sin6_family: u16(af_inet6)
				sin6_port: v_htons(dst_port)
			}
			for idx in 0 .. 16 { dest.sin6_addr[idx] = dst_ip[idx] }

			println('[\033[36m~\033[0m] Ready to fire ${count} IPv6 packets:')
			println('    From (Spoofed): ${spoof_ip_str}:${src_port}')
			println('    To (Real Target): ${target_ip_str}:${dst_port}')

			for i in 0 .. count {
				sent := C.sendto(raw_fd, voidptr(udp_pkt.data), udp_pkt.len, 0, &dest, u32(sizeof(dest)))
				if sent < 0 {
					err_msg := get_errno_msg(C.errno)
					eprintln('[\033[31m!\033[0m] Failed to send IPv6 packet #${i + 1}: ${err_msg}')
				} else {
					println('[\033[32m+\033[0m] IPv6 Packet #${i + 1} sent successfully (${sent + 40} bytes on-wire).')
				}
			}
			C.close(raw_fd)
		} $else {
			eprintln('[\033[31m!\033[0m] Windows does not natively support IPv6 raw socket operations.')
		}
	}
}