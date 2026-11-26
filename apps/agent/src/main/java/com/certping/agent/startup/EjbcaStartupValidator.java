// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.startup;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.ssl.ejbca.EjbcaSigningService;
import com.certping.agent.ssl.ejbca.EndEntityNameResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Surfaces EJBCA misconfiguration at startup instead of at the first device enrollment.
 *
 * <p>Enrollment is synchronous with a device waiting on the other end, so "the three profile
 * names were blank" is a bad thing to discover then. Like
 * {@link SecretStoreStartupValidator} this warns rather than aborting the boot: an agent with a
 * broken EJBCA config still serves its other CAs correctly.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class EjbcaStartupValidator {

    private final AgentProperties properties;
    private final EjbcaSigningService ejbcaSigningService;

    @EventListener(ApplicationReadyEvent.class)
    public void validate() {
        AgentProperties.EjbcaProperties cfg = properties.getEjbca();
        if (!cfg.isEnabled()) {
            log.debug("[EJBCA-STARTUP] disabled — skipping validation");
            return;
        }

        List<String> missing = new ArrayList<>();
        if (isBlank(cfg.getCredentialPath()) && isBlank(cfg.getCredentialsJson()))
            missing.add("agent.ejbca.credential-path or agent.ejbca.credentials-json");
        if (isBlank(cfg.getCaName()))                 missing.add("agent.ejbca.ca-name");
        if (isBlank(cfg.getCertificateProfileName())) missing.add("agent.ejbca.certificate-profile-name");
        if (isBlank(cfg.getEndEntityProfileName()))   missing.add("agent.ejbca.end-entity-profile-name");

        if (!missing.isEmpty()) {
            // pkcs10enroll rejects a request missing any of these and there is no safe default.
            log.error("[EJBCA-STARTUP] enabled but required configuration is blank: {} — "
                            + "every signing request will fail until these are set", missing);
            return;
        }

        String nameSource = cfg.getEndEntityNameSource();
        // Sourced from the resolver so the two lists cannot drift apart and bless a value the
        // resolver would then reject.
        List<String> nameSources = EndEntityNameResolver.NAME_SOURCES;
        if (!isBlank(nameSource) && !nameSources.contains(nameSource.trim().toLowerCase())) {
            log.error("[EJBCA-STARTUP] agent.ejbca.end-entity-name-source='{}' is not one of {} — "
                    + "signing will fail for requests without an explicit device id",
                    nameSource, nameSources);
            return;
        }

        try {
            // Unauthorized endpoint: a 2xx proves reachability and that REST is enabled (it is
            // disabled by default), separating those from a rejected credential.
            log.info("[EJBCA-STARTUP] reachable — {}", ejbcaSigningService.probeVersion());
        } catch (Exception e) {
            log.warn("[EJBCA-STARTUP] probe failed: {} — signing requests will fail until this "
                    + "is resolved", e.getMessage());
        }
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
