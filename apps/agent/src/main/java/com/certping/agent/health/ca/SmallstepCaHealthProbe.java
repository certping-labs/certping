// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health.ca;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.AgentException;
import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.model.message.CaConnectorHealth;
import com.certping.agent.model.message.CaConnectorStatus;
import com.certping.agent.model.message.CaHealthIssue;
import com.certping.agent.model.message.CaProductInfo;
import com.certping.agent.model.message.CaProfileRef;
import com.certping.agent.ssl.smallstep.SmallstepSigningService;
import com.certping.agent.ssl.smallstep.SmallstepRevocationService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

@Component
@ConditionalOnProperty(prefix = "agent.smallstep", name = "enabled", havingValue = "true")
@RequiredArgsConstructor
public class SmallstepCaHealthProbe implements CaHealthProbe {
    private final AgentProperties properties;
    private final SmallstepSigningService signingService;
    private final SmallstepRevocationService revocationService;

    @Override public String caProvider() { return CaProvider.SMALLSTEP.name(); }

    @Override
    public CaConnectorHealth probe() {
        AgentProperties.SmallstepProperties config = properties.getSmallstep();
        CaConnectorHealth.CaConnectorHealthBuilder health = CaConnectorHealth.builder()
                .caProvider(caProvider()).connectorId("smallstep-default").enabled(config.isEnabled())
                .checkedAt(OffsetDateTime.now(ZoneOffset.UTC).toString()).endpoint(config.getBaseUrl())
                .authMethod("JWK_PROVISIONER_TOKEN")
                .capabilities(List.of("SIGN_CSR", "REVOKE_CERTIFICATE", "CHECK_REVOCATION"));
        boolean hasCredentialPath = config.getCredentialPath() != null && !config.getCredentialPath().isBlank();
        boolean hasCredentialsJson = config.getCredentialsJson() != null && !config.getCredentialsJson().isBlank();
        if (!hasCredentialPath && !hasCredentialsJson) {
            return health.status(CaConnectorStatus.UNCONFIGURED.name())
                    .issues(List.of(issue("SMALLSTEP_CONFIG_MISSING",
                            "agent.smallstep.credential-path or agent.smallstep.credentials-json is not set")))
                    .build();
        }
        long started = System.nanoTime();
        try {
            String version = signingService.probeVersion();
            revocationService.verifyReady();
            health.endpoint(signingService.connectedEndpoint())
                    .profiles(List.of(CaProfileRef.builder().kind("PROVISIONER")
                            .name(signingService.provisionerName()).verified(true).build()))
                    .product(CaProductInfo.builder().name("step-ca").version(version).raw(version).build());
            return health.latencyMs(elapsed(started)).status(CaConnectorStatus.HEALTHY.name())
                    .issues(List.of()).build();
        } catch (AgentException exception) {
            return health.latencyMs(elapsed(started)).status(status(exception.getErrorCode()).name())
                    .issues(List.of(issue(exception.getErrorCode(), exception.getMessage()))).build();
        } catch (Exception exception) {
            return health.latencyMs(elapsed(started)).status(CaConnectorStatus.ERROR.name())
                    .issues(List.of(issue("CA_PROBE_FAILED", "Smallstep health probe failed"))).build();
        }
    }

    private static CaConnectorStatus status(String code) {
        if (code == null) return CaConnectorStatus.ERROR;
        if (code.contains("AUTH")) return CaConnectorStatus.UNAUTHORIZED;
        if (code.contains("CONFIG") || code.contains("CREDENTIAL")) return CaConnectorStatus.UNCONFIGURED;
        if (code.contains("NETWORK") || code.contains("TLS") || code.contains("SERVER")) {
            return CaConnectorStatus.UNREACHABLE;
        }
        return CaConnectorStatus.ERROR;
    }
    private static CaHealthIssue issue(String code, String message) {
        return CaHealthIssue.builder().severity("ERROR").code(code).message(message).build();
    }
    private static long elapsed(long started) {
        return Duration.ofNanos(System.nanoTime() - started).toMillis();
    }
}
