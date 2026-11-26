// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import com.certping.agent.exception.PermanentAgentException;

record NamecheapZoneHost(String sld, String tld, String domain, String hostName) {

    static NamecheapZoneHost fromRecordName(String recordName) {
        String domain = recordName.replaceFirst("^_acme-challenge\\.", "").replaceFirst("^\\*\\.", "");
        String[] parts = domain.split("\\.");
        if (parts.length < 2) {
            throw new PermanentAgentException("DNS_ZONE_NOT_FOUND",
                    "Namecheap cannot determine SLD/TLD for record: " + recordName);
        }

        String tld = parts[parts.length - 1];
        String sld = parts[parts.length - 2];
        String zone = sld + "." + tld;
        String hostName = recordName.endsWith("." + zone)
                ? recordName.substring(0, recordName.length() - zone.length() - 1)
                : "_acme-challenge";
        return new NamecheapZoneHost(sld, tld, zone, hostName);
    }
}
