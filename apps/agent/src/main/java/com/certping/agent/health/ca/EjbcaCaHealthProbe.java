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
import com.certping.agent.ssl.ejbca.EjbcaSigningService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reports on the EJBCA connector.
 *
 * <p>Registered only when {@code agent.ejbca.enabled=true}. An agent that does not use EJBCA
 * should not publish an EJBCA connector at all; one that is enabled but incompletely configured
 * still reports {@code UNCONFIGURED} naming the exact fields that are missing.
 *
 * <p>The probe is {@code GET /v1/certificate/status}, which needs no authorization. That makes a
 * 2xx meaningful on its own: the endpoint is reachable and the REST protocol is enabled — the
 * two failures most easily confused with a bad credential. It also returns version and edition
 * in one string, which is why neither is stored in the credential secret.
 */
@Slf4j
@Component
@ConditionalOnProperty(prefix = "agent.ejbca", name = "enabled", havingValue = "true")
@RequiredArgsConstructor
public class EjbcaCaHealthProbe implements CaHealthProbe {

    /** e.g. "EJBCA 9.3.7 Community (afce321eed98ab06bd8cc78e89fc50b73a5b8db4)". */
    private static final Pattern REVISION =
            Pattern.compile("EJBCA\\s+(?<version>[0-9][0-9.]*)\\s+(?<edition>\\w+)");

    /** Keyfactor's own oldest supported release. Below this we warn but do not block. */
    private static final String SUPPORTED_FLOOR = "9.3.3";

    private final AgentProperties properties;
    private final EjbcaSigningService ejbcaSigningService;

    @Override
    public String caProvider() {
        return CaProvider.EJBCA.name();
    }

    @Override
    public CaConnectorHealth probe() {
        AgentProperties.EjbcaProperties config = properties.getEjbca();
        CaConnectorHealth.CaConnectorHealthBuilder health = CaConnectorHealth.builder()
                .caProvider(caProvider())
                .connectorId("ejbca-default")
                .enabled(config.isEnabled())
                .checkedAt(now())
                .endpoint(config.getBaseUrl())
                .profiles(configuredProfiles(config))
                .capabilities(List.of("SIGN_CSR"));

        if (!config.isEnabled()) {
            return health.status(CaConnectorStatus.UNCONFIGURED.name()).issues(List.of()).build();
        }

        List<CaHealthIssue> issues = missingConfiguration(config);
        if (!issues.isEmpty()) {
            return health.status(CaConnectorStatus.UNCONFIGURED.name()).issues(issues).build();
        }

        long startedAt = System.nanoTime();
        try {
            String revision = ejbcaSigningService.probeVersion();
            health.latencyMs(elapsedMs(startedAt));

            CaProductInfo product = parseProduct(revision);
            health.product(product);
            // Both come from the credential, so they are only knowable after a session exists —
            // which the probe above has just established.
            health.authMethod(ejbcaSigningService.activeAuthMethod());
            String endpoint = ejbcaSigningService.connectedEndpoint();
            if (endpoint != null) {
                health.endpoint(endpoint);
            }

            List<CaHealthIssue> warnings = versionWarnings(product);
            return health
                    .status(warnings.isEmpty()
                            ? CaConnectorStatus.HEALTHY.name()
                            : CaConnectorStatus.DEGRADED.name())
                    .issues(warnings)
                    .build();

        } catch (AgentException e) {
            health.latencyMs(elapsedMs(startedAt));
            return health
                    .status(statusFor(e.getErrorCode()).name())
                    .issues(List.of(issueFor(e)))
                    .build();

        } catch (Exception e) {
            // A probe must never take the report down with it.
            log.warn("EJBCA health probe failed unexpectedly: {}", e.getMessage());
            health.latencyMs(elapsedMs(startedAt));
            return health
                    .status(CaConnectorStatus.ERROR.name())
                    .issues(List.of(CaHealthIssue.builder()
                            .severity("ERROR")
                            .code("CA_PROBE_FAILED")
                            .message("EJBCA health probe failed: " + e.getMessage())
                            .build()))
                    .build();
        }
    }

    private List<CaProfileRef> configuredProfiles(AgentProperties.EjbcaProperties config) {
        // verified=false throughout: EJBCA Community exposes no endpoint to enumerate profiles
        // (v1/certificateprofile and v2/certificate/profiles are both absent), so the agent can
        // report what it is configured to use but cannot confirm any of it exists.
        List<CaProfileRef> profiles = new ArrayList<>();
        addProfile(profiles, "CA", config.getCaName());
        addProfile(profiles, "CERTIFICATE_PROFILE", config.getCertificateProfileName());
        addProfile(profiles, "END_ENTITY_PROFILE", config.getEndEntityProfileName());
        return profiles;
    }

    private void addProfile(List<CaProfileRef> profiles, String kind, String name) {
        if (name != null && !name.isBlank()) {
            profiles.add(CaProfileRef.builder().kind(kind).name(name).verified(false).build());
        }
    }

    private List<CaHealthIssue> missingConfiguration(AgentProperties.EjbcaProperties config) {
        List<CaHealthIssue> issues = new ArrayList<>();
        boolean hasCredentialPath = config.getCredentialPath() != null && !config.getCredentialPath().isBlank();
        boolean hasCredentialsJson = config.getCredentialsJson() != null && !config.getCredentialsJson().isBlank();
        if (!hasCredentialPath && !hasCredentialsJson) {
            issues.add(CaHealthIssue.builder()
                    .severity("ERROR")
                    .code("CA_CONFIG_MISSING")
                    .message("agent.ejbca.credential-path or agent.ejbca.credentials-json is not set")
                    .remediation("Set agent.ejbca.credential-path or agent.ejbca.credentials-json on "
                            + "the agent. EJBCA rejects an enrollment that omits it and there is no "
                            + "safe default.")
                    .build());
        }
        requireField(issues, config.getCaName(), "agent.ejbca.ca-name");
        requireField(issues, config.getCertificateProfileName(), "agent.ejbca.certificate-profile-name");
        requireField(issues, config.getEndEntityProfileName(), "agent.ejbca.end-entity-profile-name");
        return issues;
    }

    private void requireField(List<CaHealthIssue> issues, String value, String name) {
        if (value == null || value.isBlank()) {
            issues.add(CaHealthIssue.builder()
                    .severity("ERROR")
                    .code("CA_CONFIG_MISSING")
                    .message(name + " is not set")
                    .remediation("Set " + name + " on the agent. EJBCA rejects an enrollment that "
                            + "omits it and there is no safe default.")
                    .build());
        }
    }

    private CaConnectorStatus statusFor(String errorCode) {
        if (errorCode == null) {
            return CaConnectorStatus.ERROR;
        }
        return switch (errorCode) {
            case "EJBCA_REST_DISABLED", "EJBCA_NETWORK_ERROR", "EJBCA_TLS_HANDSHAKE_FAILED",
                 "EJBCA_UNEXPECTED_REDIRECT", "EJBCA_SERVER_ERROR", "EJBCA_CONNECTION_RESET",
                 // A throttled or 503-ing CA cannot serve an enrollment right now, which is the
                 // same operator signal as unreachable — not "credential accepted but broken".
                 "CA_PROVIDER_THROTTLED" -> CaConnectorStatus.UNREACHABLE;
            case "EJBCA_AUTH_FAILED", "EJBCA_OAUTH_REJECTED", "EJBCA_CREDENTIAL_NOT_PRESENTED",
                 "EJBCA_OAUTH_TOKEN_FAILED", "EJBCA_OAUTH_TLS_FAILED" -> CaConnectorStatus.UNAUTHORIZED;
            case "EJBCA_CONFIG_MISSING", "EJBCA_CREDENTIAL_MISSING",
                 "EJBCA_CREDENTIAL_INVALID" -> CaConnectorStatus.UNCONFIGURED;
            default -> CaConnectorStatus.ERROR;
        };
    }

    private CaHealthIssue issueFor(AgentException e) {
        return CaHealthIssue.builder()
                .severity("ERROR")
                .code(e.getErrorCode())
                .message(e.getMessage())
                .remediation(remediationFor(e.getErrorCode()))
                .build();
    }

    private String remediationFor(String errorCode) {
        if (errorCode == null) {
            return null;
        }
        return switch (errorCode) {
            case "EJBCA_REST_DISABLED" -> "REST ships disabled on a fresh EJBCA. Enable it with: "
                    + "ejbca.sh config protocols enable --name \"REST Certificate Management\"";
            case "EJBCA_TLS_HANDSHAKE_FAILED" -> "Either serverCaChainPem does not match EJBCA's "
                    + "TLS issuer, or EJBCA's truststore is missing the CA that issued our client "
                    + "certificate. The second failure logs nothing on the EJBCA side.";
            case "EJBCA_CREDENTIAL_NOT_PRESENTED" -> "Check the credential secret: the P12 may have "
                    + "failed to load, or authMethod disagrees with the fields supplied.";
            case "EJBCA_OAUTH_REJECTED" -> "Check that the token's subject is an EJBCA role member "
                    + "configured with OAuth2AuthenticationToken:CLAIM_SUBJECT, and that its 'kid' "
                    + "matches a trusted OAuth provider in EJBCA.";
            case "EJBCA_UNEXPECTED_REDIRECT" -> "Point agent.ejbca.base-url at the https port. "
                    + "EJBCA redirects plain HTTP, and a redirected POST loses its body.";
            default -> null;
        };
    }

    private CaProductInfo parseProduct(String revision) {
        CaProductInfo.CaProductInfoBuilder product = CaProductInfo.builder()
                .name("EJBCA")
                .raw(revision);
        Matcher matcher = REVISION.matcher(revision == null ? "" : revision);
        if (matcher.find()) {
            product.version(matcher.group("version")).edition(matcher.group("edition"));
        }
        return product.build();
    }

    private List<CaHealthIssue> versionWarnings(CaProductInfo product) {
        if (product.getVersion() == null || !isBelow(product.getVersion(), SUPPORTED_FLOOR)) {
            return List.of();
        }
        // Warn, don't block: older releases still work, they are simply out of support.
        return List.of(CaHealthIssue.builder()
                .severity("WARN")
                .code("CA_VERSION_UNSUPPORTED")
                .message("EJBCA " + product.getVersion() + " is below Keyfactor's oldest supported "
                        + "release (" + SUPPORTED_FLOOR + ")")
                .remediation("Upgrade EJBCA. Issuance still works today; this is a support-window "
                        + "warning, not an outage.")
                .build());
    }

    private boolean isBelow(String version, String floor) {
        String[] actual = version.split("\\.");
        String[] minimum = floor.split("\\.");
        for (int i = 0; i < Math.max(actual.length, minimum.length); i++) {
            int left = i < actual.length ? parse(actual[i]) : 0;
            int right = i < minimum.length ? parse(minimum[i]) : 0;
            if (left != right) {
                return left < right;
            }
        }
        return false;
    }

    private int parse(String value) {
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private long elapsedMs(long startedAtNanos) {
        return Duration.ofNanos(System.nanoTime() - startedAtNanos).toMillis();
    }

    private String now() {
        return OffsetDateTime.now(ZoneOffset.UTC).toString();
    }
}
