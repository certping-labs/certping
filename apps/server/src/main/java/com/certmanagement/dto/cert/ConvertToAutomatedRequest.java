// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.cert;

import com.certmanagement.validation.ValidDomain;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;

/**
 * When provided, deploymentTargets overrides the stored deployment_targets
 * for this certificate's domain config. deploymentTargetConfigs allows
 * per-target config to be set inline (e.g. Azure KV certificateName).
 */
@Data
public class ConvertToAutomatedRequest {

    @NotEmpty
    @Valid
    private List<DnsCredentialMapping> dnsMappings;

    private List<String> deploymentTargets;

    /** Optional per-target deployment config (same shape as CertIssuanceRequest). */
    @Valid
    private List<CertIssuanceRequest.DeploymentTargetConfigEntry> deploymentTargetConfigs;

    private ActivationMode activationMode;

    private InFlightPolicy inFlightPolicy;

    @Data
    public static class DnsCredentialMapping {

        @NotBlank
        @ValidDomain
        private String domain;

        @NotBlank
        private String credentialXref;
    }

    public enum ActivationMode {
        IMMEDIATE,
        NEXT_RENEWAL
    }

    public enum InFlightPolicy {
        WAIT,
        CANCEL_AND_REISSUE
    }
}
