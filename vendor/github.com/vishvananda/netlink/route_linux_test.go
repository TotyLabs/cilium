//go:build linux
// +build linux

package netlink

import (
	"bytes"
	"net"
	"testing"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// TestDeserializeRouteRejectsUndersizedAddresses verifies that deserializeRoute
// rejects route address attributes that are shorter than the address family width.
func TestDeserializeRouteRejectsUndersizedAddresses(t *testing.T) {
	tests := []struct {
		name      string
		family    int
		attrType  uint16
		attrValue []byte
		wantErr   bool
		desc      string
	}{
		// IPv4 tests
		{
			name:      "IPv4_RTA_DST_3bytes",
			family:    unix.AF_INET,
			attrType:  unix.RTA_DST,
			attrValue: []byte{192, 168, 0}, // 3 bytes, should be rejected
			wantErr:   true,
			desc:      "IPv4 RTA_DST with 3 bytes should be rejected",
		},
		{
			name:      "IPv4_RTA_DST_4bytes",
			family:    unix.AF_INET,
			attrType:  unix.RTA_DST,
			attrValue: []byte{192, 168, 0, 0}, // 4 bytes, valid
			wantErr:   false,
			desc:      "IPv4 RTA_DST with 4 bytes should be accepted",
		},
		{
			name:      "IPv4_RTA_DST_8bytes",
			family:    unix.AF_INET,
			attrType:  unix.RTA_DST,
			attrValue: []byte{192, 168, 0, 0, 255, 255, 255, 255}, // 8 bytes, should clamp to 4
			wantErr:   false,
			desc:      "IPv4 RTA_DST with 8 bytes should be accepted and clamped",
		},
		{
			name:      "IPv4_RTA_GATEWAY_3bytes",
			family:    unix.AF_INET,
			attrType:  unix.RTA_GATEWAY,
			attrValue: []byte{10, 0, 0}, // 3 bytes, should be rejected
			wantErr:   true,
			desc:      "IPv4 RTA_GATEWAY with 3 bytes should be rejected",
		},
		{
			name:      "IPv4_RTA_GATEWAY_4bytes",
			family:    unix.AF_INET,
			attrType:  unix.RTA_GATEWAY,
			attrValue: []byte{10, 0, 0, 1}, // 4 bytes, valid
			wantErr:   false,
			desc:      "IPv4 RTA_GATEWAY with 4 bytes should be accepted",
		},
		{
			name:      "IPv4_RTA_PREFSRC_3bytes",
			family:    unix.AF_INET,
			attrType:  unix.RTA_PREFSRC,
			attrValue: []byte{172, 16, 0}, // 3 bytes, should be rejected
			wantErr:   true,
			desc:      "IPv4 RTA_PREFSRC with 3 bytes should be rejected",
		},
		{
			name:      "IPv4_RTA_PREFSRC_4bytes",
			family:    unix.AF_INET,
			attrType:  unix.RTA_PREFSRC,
			attrValue: []byte{172, 16, 0, 1}, // 4 bytes, valid
			wantErr:   false,
			desc:      "IPv4 RTA_PREFSRC with 4 bytes should be accepted",
		},

		// IPv6 tests
		{
			name:      "IPv6_RTA_DST_15bytes",
			family:    unix.AF_INET6,
			attrType:  unix.RTA_DST,
			attrValue: make([]byte, 15), // 15 bytes, should be rejected
			wantErr:   true,
			desc:      "IPv6 RTA_DST with 15 bytes should be rejected",
		},
		{
			name:      "IPv6_RTA_DST_16bytes",
			family:    unix.AF_INET6,
			attrType:  unix.RTA_DST,
			attrValue: make([]byte, 16), // 16 bytes, valid
			wantErr:   false,
			desc:      "IPv6 RTA_DST with 16 bytes should be accepted",
		},
		{
			name:      "IPv6_RTA_DST_32bytes",
			family:    unix.AF_INET6,
			attrType:  unix.RTA_DST,
			attrValue: make([]byte, 32), // 32 bytes, should clamp to 16
			wantErr:   false,
			desc:      "IPv6 RTA_DST with 32 bytes should be accepted and clamped",
		},
		{
			name:      "IPv6_RTA_GATEWAY_15bytes",
			family:    unix.AF_INET6,
			attrType:  unix.RTA_GATEWAY,
			attrValue: make([]byte, 15), // 15 bytes, should be rejected
			wantErr:   true,
			desc:      "IPv6 RTA_GATEWAY with 15 bytes should be rejected",
		},
		{
			name:      "IPv6_RTA_GATEWAY_16bytes",
			family:    unix.AF_INET6,
			attrType:  unix.RTA_GATEWAY,
			attrValue: make([]byte, 16), // 16 bytes, valid
			wantErr:   false,
			desc:      "IPv6 RTA_GATEWAY with 16 bytes should be accepted",
		},
		{
			name:      "IPv6_RTA_PREFSRC_15bytes",
			family:    unix.AF_INET6,
			attrType:  unix.RTA_PREFSRC,
			attrValue: make([]byte, 15), // 15 bytes, should be rejected
			wantErr:   true,
			desc:      "IPv6 RTA_PREFSRC with 15 bytes should be rejected",
		},
		{
			name:      "IPv6_RTA_PREFSRC_16bytes",
			family:    unix.AF_INET6,
			attrType:  unix.RTA_PREFSRC,
			attrValue: make([]byte, 16), // 16 bytes, valid
			wantErr:   false,
			desc:      "IPv6 RTA_PREFSRC with 16 bytes should be accepted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Construct minimal RtMsg with the test attribute
			msg := buildRtMsg(tt.family, 16, tt.attrType, tt.attrValue)
			route, err := deserializeRoute(msg)

			if (err != nil) != tt.wantErr {
				t.Errorf("%s: got err=%v, wantErr=%v", tt.desc, err, tt.wantErr)
				return
			}

			// For valid cases, verify the address was deserialized correctly
			if !tt.wantErr {
				switch tt.attrType {
				case unix.RTA_DST:
					if route.Dst == nil {
						t.Errorf("%s: expected non-nil Dst, got nil", tt.desc)
						return
					}
					// Verify mask width is correct for address family
					_, bits := route.Dst.Mask.Size()
					expectedBits := 32
					if tt.family == unix.AF_INET6 {
						expectedBits = 128
					}
					if bits != expectedBits {
						t.Errorf("%s: mask width %d != %d", tt.desc, bits, expectedBits)
					}
					// Verify IP length matches family
					expectedLen := 4
					if tt.family == unix.AF_INET6 {
						expectedLen = 16
					}
					if len(route.Dst.IP) != expectedLen {
						t.Errorf("%s: IP length %d != %d", tt.desc, len(route.Dst.IP), expectedLen)
					}

				case unix.RTA_GATEWAY:
					if route.Gw == nil {
						t.Errorf("%s: expected non-nil Gw, got nil", tt.desc)
						return
					}
					// Verify address length matches family
					expectedLen := 4
					if tt.family == unix.AF_INET6 {
						expectedLen = 16
					}
					if len(route.Gw) != expectedLen {
						t.Errorf("%s: Gw length %d != %d", tt.desc, len(route.Gw), expectedLen)
					}

				case unix.RTA_PREFSRC:
					if route.Src == nil {
						t.Errorf("%s: expected non-nil Src, got nil", tt.desc)
						return
					}
					// Verify address length matches family
					expectedLen := 4
					if tt.family == unix.AF_INET6 {
						expectedLen = 16
					}
					if len(route.Src) != expectedLen {
						t.Errorf("%s: Src length %d != %d", tt.desc, len(route.Src), expectedLen)
					}
				}
			}
		})
	}
}

// TestDeserializeRouteBufferAliasingFix verifies the original buffer aliasing
// vulnerability is fixed: oversized RTA_DST attributes no longer propagate
// adjacent buffer data into the route destination.
func TestDeserializeRouteBufferAliasingFix(t *testing.T) {
	// Construct a message with oversized RTA_DST
	// Real IP: 192.168.0.0
	// Adjacent data (simulating corrupted Len): "ens9" bytes
	ipBytes := []byte{192, 168, 0, 0}
	corruptionBytes := []byte{101, 110, 115, 57} // ASCII "ens9"
	oversizedPayload := append(ipBytes, corruptionBytes...)

	msg := buildRtMsg(unix.AF_INET, 16, unix.RTA_DST, oversizedPayload)
	route, err := deserializeRoute(msg)

	if err != nil {
		t.Fatalf("deserializeRoute failed: %v", err)
	}

	if route.Dst == nil {
		t.Fatal("expected non-nil Dst")
	}

	// Verify the IP is exactly 4 bytes and matches the real address
	if len(route.Dst.IP) != 4 {
		t.Errorf("expected IP length 4, got %d", len(route.Dst.IP))
	}

	expectedIP := net.IPv4(192, 168, 0, 0)
	if !route.Dst.IP.Equal(expectedIP) {
		t.Errorf("expected IP %v, got %v", expectedIP, route.Dst.IP)
	}

	// Verify mask width is correct (32 for IPv4)
	_, bits := route.Dst.Mask.Size()
	if bits != 32 {
		t.Errorf("expected mask bits 32, got %d", bits)
	}

	// Verify the corruption bytes were not included
	if bytes.Contains(route.Dst.IP, corruptionBytes) {
		t.Error("route IP contains corruption bytes from adjacent buffer")
	}
}

// buildRtMsg constructs a minimal netlink RtMsg with a single attribute for testing.
func buildRtMsg(family int, dstLen uint8, attrType uint16, attrValue []byte) []byte {
	rtMsg := nl.NewRtMsg()
	rtMsg.Family = uint8(family)
	rtMsg.Dst_len = dstLen
	rtMsg.Src_len = 0
	rtMsg.Tos = 0
	rtMsg.Table = 0
	rtMsg.Protocol = 0
	rtMsg.Scope = 0
	rtMsg.Type = 0
	rtMsg.Flags = 0

	attr := nl.NewRtAttr(int(attrType), attrValue)
	return append(rtMsg.Serialize(), attr.Serialize()...)
}
