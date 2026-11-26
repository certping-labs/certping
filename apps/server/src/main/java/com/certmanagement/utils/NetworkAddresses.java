// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.utils;

import java.net.InetAddress;

/** SSRF guard shared by every fetch of a user-supplied URL or host. */
public final class NetworkAddresses {

    private NetworkAddresses() {
    }

    /**
     * True for loopback, wildcard, link-local (incl. the cloud metadata endpoint 169.254.169.254),
     * RFC 1918, multicast, carrier-grade NAT and IPv6 unique-local addresses.
     */
    public static boolean isNonPublic(InetAddress address) {
        if (address.isLoopbackAddress()
                || address.isAnyLocalAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }
        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            int b0 = bytes[0] & 0xFF;
            int b1 = bytes[1] & 0xFF;
            return b0 == 100 && b1 >= 64 && b1 <= 127;
        }
        // fc00::/7; Java has no isSiteLocal equivalent for these.
        return bytes.length == 16 && (bytes[0] & 0xFE) == 0xFC;
    }
}
