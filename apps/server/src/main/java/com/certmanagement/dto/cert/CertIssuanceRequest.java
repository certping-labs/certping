// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.cert;

import com.certmanagement.dto.credconfig.KubernetesDeploymentConfigRequest;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.validation.ValidDomain;
import com.certmanagement.validation.ValidSanPattern;
import tools.jackson.databind.JsonNode;
import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class CertIssuanceRequest {

    @NotBlank
    @ValidDomain
    private String domain;

    @NotNull
    private Boolean wildcard;

    @NotNull
    private Boolean san;

    @NotNull
    private CaProvider caProvider;

    @NotBlank
    private String dnsCredentialXref;

    private String acmeCredentialXref;

    private String caCredentialXref;

    /**
     * Requested certificate validity in days. Honored only by DigiCert and GlobalSign.
     * Let's Encrypt chooses the lifetime
     * itself (90 days historically, shorter on newer profiles; about 64 days observed), so
     * the field is ignored for it and the agent logs a warning.
     *
     * <p>When omitted, the CA's default applies (the agent asks DigiCert for 90 days).
     *
     * <p>Per CA/Browser Forum Baseline Requirements, public TLS max validity is dropping
     * over time: 200 days from 2026-03-15, 100 days from 2027-03-15, 47 days from
     * 2029-03-15. We allow up to 398 here for forward-compatibility but each CA enforces
     * its own cap server-side — DigiCert auto-truncates to 199d as of 2026-02-24,
     * GlobalSign per validation policy.
     */
    @Min(1)
    @Max(398)
    private Integer validityDays;

    @Valid
    private List<SanDomainEntry> sanDomainEntries;

    // ── CA-specific cross-field constraints ──────────────────────────────────

    @AssertTrue(message = "GlobalSign does not support wildcard patterns in SAN entries — remove any '*.domain' patterns from sanDomainEntries")
    public boolean isSanWildcardValidForCa() {
        if (CaProvider.GLOBALSIGN != caProvider || sanDomainEntries == null) {
            return true;
        }
        return sanDomainEntries.stream()
                .filter(e -> e.getPatterns() != null)
                .flatMap(e -> e.getPatterns().stream())
                .noneMatch(p -> p != null && p.startsWith("*."));
    }

    /**
     * Ordered list of deployment credentialXrefs.
     * After successful issuance, a CertDeploymentCommand is published
     * simultaneously for every xref in this list.
     * Empty list = no auto-deployment. Each xref must be type=DEPLOYMENT.
     */
    private List<String> deploymentTargets;

    /**
     * Optional per-target deployment config, used during automated issuance.
     * For KUBERNETES_SECRETS: use the {@code config} field (nsSecretMap).
     * For other providers (e.g. AZURE_KV): use the {@code targets} field (provider-specific JSON).
     */
    @Valid
    private List<DeploymentTargetConfigEntry> deploymentTargetConfigs;

    /** Optional CA-specific options passed through to the agent. */
    private Map<String, String> caOptions;

    @Data
    public static class SanDomainEntry {

        @NotEmpty
        private List<@ValidSanPattern String> patterns;

        @NotBlank
        private String dnsCredentialXref;
    }

    @Data
    public static class DeploymentTargetConfigEntry {
        @NotBlank
        private String deploymentCredentialXref;

        /** KUBERNETES_SECRETS — legacy nsSecretMap config (useDefault + nsSecretMap). */
        @Valid
        private KubernetesDeploymentConfigRequest config;

        /**
         * Generic provider-specific targets (non-Kubernetes).
         * E.g. for AZURE_KV: {@code {"certificateName":"wildcard-prod"}}
         */
        private JsonNode targets;
    }
}
