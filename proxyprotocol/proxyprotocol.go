// Copyright 2019 Path Network, Inc. All rights reserved.
// Copyright 2024 Konrad Zemek <konrad.zemek@gmail.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxyprotocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"

	"github.com/DaybreakLabs/go-mmproxy/utils"
)

// isIPv4MappedIPv6 checks if an address is in the IPv4-mapped IPv6 format (::ffff:IPv4)
func isIPv4MappedIPv6(addr []byte) bool {
	return len(addr) >= 16 && addr[10] == 0xff && addr[11] == 0xff
}

func readRemoteAddrSPP(ctrlBuf []byte) (saddr, daddr netip.AddrPort, data []byte, resultErr error) {
	// Ensure the buffer is large enough for the SPP header (38 bytes)
	if len(ctrlBuf) < 38 {
		resultErr = fmt.Errorf("incomplete SPP header")
		return
	}

	// Validate the magic number (0x56EC)
	magic := binary.BigEndian.Uint16(ctrlBuf[:2])
	if magic != 0x56EC {
		resultErr = fmt.Errorf("invalid magic number 0x%X", magic)
		return
	}

	// Extract the client and target addresses
	clientAddrBytes := ctrlBuf[2:18]
	targetAddrBytes := ctrlBuf[18:34]
	clientPort := binary.BigEndian.Uint16(ctrlBuf[34:36])
	targetPort := binary.BigEndian.Uint16(ctrlBuf[36:38])

	// Convert client and target addresses to netip.Addr
	var clientIP, targetIP netip.Addr

	// Check if the client address is IPv4-mapped IPv6
	if isIPv4MappedIPv6(clientAddrBytes) {
		// IPv4-mapped IPv6 address, take the last 4 bytes as an IPv4 address
		clientIP, _ = netip.AddrFromSlice(clientAddrBytes[12:])
	} else {
		// Otherwise, treat as IPv6 address
		clientIP, _ = netip.AddrFromSlice(clientAddrBytes)
	}

	// Check if the target address is IPv4-mapped IPv6
	if isIPv4MappedIPv6(targetAddrBytes) {
		// IPv4-mapped IPv6 address, take the last 4 bytes as an IPv4 address
		targetIP, _ = netip.AddrFromSlice(targetAddrBytes[12:])
	} else {
		// Otherwise, treat as IPv6 address
		targetIP, _ = netip.AddrFromSlice(targetAddrBytes)
	}

	// Validate that client and target addresses are valid IPv4 or IPv6
	if !clientIP.Is4() && !clientIP.Is6() {
		resultErr = fmt.Errorf("client address is not valid IPv4 or IPv6")
		return
	}
	if !targetIP.Is4() && !targetIP.Is6() {
		resultErr = fmt.Errorf("target address is not valid IPv4 or IPv6")
		return
	}

	// Construct AddrPort from the client and target addresses and ports
	saddr = netip.AddrPortFrom(clientIP, clientPort)
	daddr = netip.AddrPortFrom(targetIP, targetPort)

	// Data follows after the header (38 bytes)
	data = ctrlBuf[38:]

	return
}

func readRemoteAddrPROXYv2(ctrlBuf []byte, protocol utils.Protocol) (saddr, daddr netip.AddrPort, data []byte, resultErr error) {
	if (ctrlBuf[12] >> 4) != 2 {
		resultErr = fmt.Errorf("unknown protocol version %d", ctrlBuf[12]>>4)
		return
	}

	if ctrlBuf[12]&0xF > 1 {
		resultErr = fmt.Errorf("unknown command %d", ctrlBuf[12]&0xF)
		return
	}

	if ctrlBuf[12]&0xF == 1 && ((protocol == utils.TCP && ctrlBuf[13] != 0x11 && ctrlBuf[13] != 0x21) ||
		(protocol == utils.UDP && ctrlBuf[13] != 0x12 && ctrlBuf[13] != 0x22)) {
		resultErr = fmt.Errorf("invalid family/protocol %d/%d", ctrlBuf[13]>>4, ctrlBuf[13]&0xF)
		return
	}

	var dataLen uint16
	reader := bytes.NewReader(ctrlBuf[14:16])
	if err := binary.Read(reader, binary.BigEndian, &dataLen); err != nil {
		resultErr = fmt.Errorf("failed to decode address data length: %w", err)
		return
	}

	if len(ctrlBuf) < 16+int(dataLen) {
		resultErr = fmt.Errorf("incomplete PROXY header")
		return
	}

	if ctrlBuf[12]&0xF == 0 { // LOCAL
		data = ctrlBuf[16+dataLen:]
		return
	}

	var sport, dport uint16
	if ctrlBuf[13]>>4 == 0x1 { // IPv4
		reader = bytes.NewReader(ctrlBuf[24:])
	} else {
		reader = bytes.NewReader(ctrlBuf[48:])
	}
	if err := binary.Read(reader, binary.BigEndian, &sport); err != nil {
		resultErr = fmt.Errorf("failed to decode source port: %w", err)
		return
	}
	if sport == 0 {
		resultErr = fmt.Errorf("invalid source port %d", sport)
		return
	}
	if err := binary.Read(reader, binary.BigEndian, &dport); err != nil {
		resultErr = fmt.Errorf("failed to decode destination port: %w", err)
		return
	}
	if dport == 0 {
		resultErr = fmt.Errorf("invalid destination port %d", sport)
		return
	}

	var srcIP, dstIP netip.Addr
	if ctrlBuf[13]>>4 == 0x1 { // IPv4
		srcIP, _ = netip.AddrFromSlice(ctrlBuf[16:20])
		dstIP, _ = netip.AddrFromSlice(ctrlBuf[20:24])
	} else {
		srcIP, _ = netip.AddrFromSlice(ctrlBuf[16:32])
		dstIP, _ = netip.AddrFromSlice(ctrlBuf[32:48])
	}

	saddr = netip.AddrPortFrom(srcIP, sport)
	daddr = netip.AddrPortFrom(dstIP, dport)
	data = ctrlBuf[16+dataLen:]
	return
}

func readRemoteAddrPROXYv1(ctrlBuf []byte) (saddr, daddr netip.AddrPort, data []byte, resultErr error) {
	str := string(ctrlBuf)
	idx := strings.Index(str, "\r\n")
	if idx < 0 {
		resultErr = fmt.Errorf("did not find \\r\\n in first data segment")
		return
	}

	var headerProtocol string
	n, err := fmt.Sscanf(str, "PROXY %s", &headerProtocol)
	if err != nil {
		resultErr = err
		return
	}
	if n != 1 {
		resultErr = fmt.Errorf("failed to decode elements")
		return
	}
	if headerProtocol == "UNKNOWN" {
		data = ctrlBuf[idx+2:]
		return
	}
	if headerProtocol != "TCP4" && headerProtocol != "TCP6" {
		resultErr = fmt.Errorf("unknown protocol %s", headerProtocol)
		return
	}

	var src, dst string
	var sport, dport int
	n, err = fmt.Sscanf(str, "PROXY %s %s %s %d %d", &headerProtocol, &src, &dst, &sport, &dport)
	if err != nil {
		resultErr = err
		return
	}
	if n != 5 {
		resultErr = fmt.Errorf("failed to decode elements")
		return
	}
	if sport <= 0 || sport > 65535 {
		resultErr = fmt.Errorf("invalid source port %d", sport)
		return
	}
	if dport <= 0 || dport > 65535 {
		resultErr = fmt.Errorf("invalid destination port %d", sport)
		return
	}
	srcIP, err := netip.ParseAddr(src)
	if err != nil {
		resultErr = fmt.Errorf("failed to parse source IP address %s: %w", src, err)
		return
	}
	dstIP, err := netip.ParseAddr(dst)
	if err != nil {
		resultErr = fmt.Errorf("failed to parse destination IP address %s: %w", dst, err)
		return
	}

	saddr = netip.AddrPortFrom(srcIP, uint16(sport))
	daddr = netip.AddrPortFrom(dstIP, uint16(dport))
	data = ctrlBuf[idx+2:]
	return
}

var proxyv2header = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

func ReadRemoteAddr(buf []byte, protocol utils.Protocol) (saddr, daddr netip.AddrPort, rest []byte, err error) {
	if protocol == utils.UDP && len(buf) >= 38 {
		saddr, daddr, rest, err = readRemoteAddrSPP(buf)
		if err != nil {
			err = fmt.Errorf("failed to parse SPP header: %w", err)
		}
		// Ignore if failed to parse SPP header
	}
	if len(buf) >= 16 && bytes.Equal(buf[:12], proxyv2header) {
		saddr, daddr, rest, err = readRemoteAddrPROXYv2(buf, protocol)
		if err != nil {
			err = fmt.Errorf("failed to parse PROXY v2 header: %w", err)
		}
		return
	}

	// PROXYv1 only works with TCP
	if protocol == utils.TCP && len(buf) >= 8 && bytes.Equal(buf[:5], []byte("PROXY")) {
		saddr, daddr, rest, err = readRemoteAddrPROXYv1(buf)
		if err != nil {
			err = fmt.Errorf("failed to parse PROXY v1 header: %w", err)
		}
		return
	}

	err = fmt.Errorf("PROXY header missing")
	return
}
