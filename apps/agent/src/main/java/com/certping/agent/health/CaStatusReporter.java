// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.handler.acme.AcmeAccountService;
import com.certping.agent.model.message.CaStatus;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;

/**
 * Builds the {@link CaStatus} sent with each heartbeat: the ACME directory and this organization's
 * account on it, and whether GlobalSign is configured. Metadata only, never a key.
 *
 * <p>Reading the account means one read of the secret store, so the result is cached: it is rebuilt
 * when the ACME account metadata changes (a new or newly found account) and at most once per
 * {@link #REFRESH} otherwise.
 */
@Slf4j
@Component
public class CaStatusReporter {

    static final Duration REFRESH = Duration.ofMinutes(30);
    static final String LE_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory";
    static final String LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory";

    private final AgentProperties properties;
    private final AcmeAccountService acmeAccounts;
    private final Clock clock;

    private CaStatus cached;
    private Instant builtAt = Instant.EPOCH;
    private long builtFromVersion = -1;
    private long reportedVersion = -1;

    @Autowired
    public CaStatusReporter(AgentProperties properties, AcmeAccountService acmeAccounts) {
        this(properties, acmeAccounts, Clock.systemUTC());
    }

    CaStatusReporter(AgentProperties properties, AcmeAccountService acmeAccounts, Clock clock) {
        this.properties = properties;
        this.acmeAccounts = acmeAccounts;
        this.clock = clock;
    }

    /** True when the ACME account changed since the last report, so a heartbeat should go out now. */
    public synchronized boolean changedSinceLastReport() {
        return acmeAccounts.metadataVersion() != reportedVersion;
    }

    /** The status for the next heartbeat; marks it reported. */
    public synchronized CaStatus current() {
        long version = acmeAccounts.metadataVersion();
        Instant now = clock.instant();
        if (cached == null || version != builtFromVersion || !now.isBefore(builtAt.plus(REFRESH))) {
            cached = build(cached);
            builtAt = now;
            builtFromVersion = version;
        }
        reportedVersion = version;
        return cached;
    }

    private CaStatus build(CaStatus previous) {
        return CaStatus.builder()
                .acme(acme(previous == null ? null : previous.getAcme()))
                .globalsign(new CaStatus.Configured(globalSignConfigured()))
                .build();
    }

    private CaStatus.Acme acme(CaStatus.Acme previous) {
        String directoryUrl = properties.getAcme().getDirectoryUrl();
        if (!notBlank(directoryUrl)) {
            return null;
        }
        String organizationId = properties.getOrganizationId();
        List<CaStatus.AcmeAccount> accounts;
        try {
            accounts = acmeAccounts.describeAccount(organizationId)
                    .map(d -> CaStatus.AcmeAccount.builder()
                            .organizationId(d.organizationId())
                            .accountUrl(d.accountUrl())
                            .keyType(d.keyType())
                            .createdAt(d.createdAt() == null ? null : d.createdAt().toString())
                            .build())
                    .map(List::of)
                    .orElse(List.of());
        } catch (RuntimeException e) {
            // The secret store is unreachable for now: keep what was last reported.
            log.warn("Could not read the ACME account for the CA status report: {}", e.getMessage());
            accounts = previous == null || previous.getAccounts() == null ? List.of() : previous.getAccounts();
        }
        return CaStatus.Acme.builder()
                .directoryUrl(directoryUrl.trim())
                .environment(environmentOf(directoryUrl))
                .contactEmail(contactEmail(organizationId))
                .accounts(accounts)
                .build();
    }

    private String contactEmail(String organizationId) {
        String contact = properties.getAcme().getAccountContact();
        if (!notBlank(contact)) {
            return "";
        }
        return contact.trim().replace("{organizationId}", organizationId == null ? "" : organizationId);
    }

    private boolean globalSignConfigured() {
        AgentProperties.GlobalSignProperties gs = properties.getGlobalsign();
        return notBlank(gs.getApiKey()) && notBlank(gs.getApiSecret()) && notBlank(gs.getApiBaseUrl());
    }

    static String environmentOf(String directoryUrl) {
        String normalized = normalize(directoryUrl);
        if (normalize(LE_PRODUCTION).equals(normalized)) {
            return "PRODUCTION";
        }
        if (normalize(LE_STAGING).equals(normalized)) {
            return "STAGING";
        }
        return "CUSTOM";
    }

    private static String normalize(String url) {
        String raw = url == null ? "" : url.trim();
        try {
            URI uri = URI.create(raw);
            if (uri.getScheme() != null && uri.getHost() != null) {
                String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
                int port = uri.getPort();
                boolean defaultPort = port == -1 || ("https".equals(scheme) && port == 443);
                raw = scheme + "://" + uri.getHost().toLowerCase(Locale.ROOT) + (defaultPort ? "" : ":" + port)
                        + (uri.getRawPath() == null ? "" : uri.getRawPath());
            }
        } catch (IllegalArgumentException ignored) {
            // Not a URI: compared as typed.
        }
        while (raw.endsWith("/")) {
            raw = raw.substring(0, raw.length() - 1);
        }
        return raw;
    }

    private static boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }
}
