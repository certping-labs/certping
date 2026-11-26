// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

record NamecheapDnsRecord(
        String name,
        String type,
        String address,
        String mxPref,
        String ttl,
        String flag,
        String tag
) {

    boolean matches(DnsRecordType recordType, String hostName, String value) {
        return recordType.name().equalsIgnoreCase(type)
                && name.equalsIgnoreCase(hostName)
                && (recordType == DnsRecordType.CNAME ? sameHostName(address, value) : address.equals(value));
    }

    private static boolean sameHostName(String a, String b) {
        return withoutTrailingDot(a).equalsIgnoreCase(withoutTrailingDot(b));
    }

    private static String withoutTrailingDot(String name) {
        return name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
    }
}
