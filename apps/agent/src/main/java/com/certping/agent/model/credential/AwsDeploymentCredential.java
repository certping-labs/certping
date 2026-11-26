// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.credential;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

/**
 * AWS KV secret payload — sensitive auth only.
 *
 * <p>Both fields are nullable. Empty/null for {@code INSTANCE_PROFILE} mode (agent uses
 * ambient AWS identity / IRSA). For {@code ASSUME_ROLE} the keys are bootstrap creds for
 * STS — also optional if the agent has its own ambient identity.
 *
 * <p>All non-sensitive AWS config (region, roleArn, listener/distribution/domain plans,
 * allow-lists) lives in {@code credentialScopeJson} (scope) and {@code targetsJson} (per-cert plan).
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class AwsDeploymentCredential {
    private String accessKeyId;
    private String secretAccessKey;
}
