// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig.credjson.deployment;

import com.certmanagement.dto.credconfig.credjson.CredJsonPayload;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

/**
 * Cloudflare Edge (Custom SSL) deployment.
 *
 * <p><b>Required:</b> {@code apiToken}. Agent throws when null/blank.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class CloudflareEdgeDeploymentCredJson implements CredJsonPayload {
    private String apiToken;
}
