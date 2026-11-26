// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

record NamecheapRecordId(String hostName, String domain, String value) {

    static String encode(NamecheapZoneHost zoneHost, String value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        String hash = HexFormat.of().formatHex(digest);
        return zoneHost.hostName() + ":" + zoneHost.domain() + ":" + hash + ":" + value;
    }

    static NamecheapRecordId parse(String recordId) {
        if (recordId == null || recordId.isBlank()) {
            throw new IllegalArgumentException("recordId is blank");
        }
        String[] parts = recordId.split(":", 4);
        if (parts.length != 4) {
            throw new IllegalArgumentException("invalid recordId format");
        }
        return new NamecheapRecordId(parts[0], parts[1], parts[3]);
    }
}
