// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

@Slf4j
@Component
public class DnsTxtCleanupService {

    public void cleanup(List<DnsTxtCleanupEntry> entries) {
        for (DnsTxtCleanupEntry entry : entries) {
            try {
                entry.provider().deleteTxtRecord(entry.recordName(), entry.recordId());
            } catch (Exception e) {
                // Cleanup is best-effort hygiene that runs AFTER the certificate workflow finishes
                // (success or failure). We deliberately swallow even a RetryableAgentException
                // raised by a throttled DNS provider here — re-enqueuing the original message would
                // re-run the entire workflow (re-issuance, re-validation), which is far worse than
                // leaking one TXT record. A failed delete leaves the record in place; later
                // issuances add new records rather than removing it, so it stays until removed by
                // hand.
                log.warn("DNS TXT cleanup failed for {}: {}", entry.recordName(), e.getMessage());
            }
        }
    }

    public record DnsTxtCleanupEntry(DnsProvider provider, String recordName, String recordId) {}
}