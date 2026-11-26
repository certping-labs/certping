// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;

@Slf4j
@Component
public class DnsProviderSelector {

    public DnsProvider selectProvider(String authDomain,
                                      String rootDomain,
                                      DnsProvider rootDnsProvider,
                                      Map<String, DnsProvider> sanDnsProviders) {
        if (sanDnsProviders == null || sanDnsProviders.isEmpty()) {
            return rootDnsProvider;
        }
        if (authDomain.equals(rootDomain)) {
            return rootDnsProvider;
        }

        DnsProvider exact = sanDnsProviders.get(authDomain);
        if (exact != null) {
            return exact;
        }

        for (Map.Entry<String, DnsProvider> entry : sanDnsProviders.entrySet()) {
            String pattern = entry.getKey();
            if (pattern != null && pattern.startsWith("*.")) {
                String base = pattern.substring(2);
                if (authDomain.endsWith("." + base)) {
                    String sub = authDomain.substring(0, authDomain.length() - base.length() - 1);
                    if (!sub.contains(".")) {
                        return entry.getValue();
                    }
                }
            }
        }

        log.warn("No SAN provider pattern matched authDomain='{}' - falling back to root provider", authDomain);
        return rootDnsProvider;
    }
}