// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig.credjson.deployment;

import com.certmanagement.dto.credconfig.credjson.CredJsonPayload;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

/**
 * Mirrors agent {@code AwsDeploymentCredential} — sensitive auth fields only.
 *
 * <p><b>All fields OPTIONAL.</b> Omit both when the agent should use ambient identity
 * (IRSA / EC2 instance profile / workload identity). If supplied, both must be present together
 * for static IAM auth.
 *
 * <p>Non-sensitive config (region, roleArn, listener/distribution plans) belongs in
 * {@code configJson}, not here.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class AwsDeploymentCredJson implements CredJsonPayload {
    private String accessKeyId;
    private String secretAccessKey;
}
