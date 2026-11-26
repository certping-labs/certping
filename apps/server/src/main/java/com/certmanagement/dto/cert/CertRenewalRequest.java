// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.cert;

import lombok.Data;

import java.util.List;

/**
 * Optional request body for POST /api/v1/certs/{certXref}/renew.
 *
 * When provided, deploymentTargets overrides the stored deployment_targets
 * for this renewal only AND updates domain_credential_config for future renewals.
 * Null / empty = use the stored domain_credential_config.deployment_targets.
 */
@Data
public class CertRenewalRequest {

    /**
     * Optional override for deployment targets.
     * If null or empty, the current domain_credential_config.deployment_targets are used.
     * If provided, these replace deployment_targets for this renewal AND update the config.
     */
    private List<String> deploymentTargets;
}
