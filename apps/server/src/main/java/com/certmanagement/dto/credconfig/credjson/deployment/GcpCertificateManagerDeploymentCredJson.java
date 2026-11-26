// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig.credjson.deployment;

import com.certmanagement.dto.credconfig.credjson.CredJsonPayload;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import tools.jackson.databind.JsonNode;
import lombok.Data;

/**
 * GCP Certificate Manager / ALB / Proxy NLB / Cloud CDN deployment.
 *
 * <p><b>All fields OPTIONAL.</b> Supply exactly one of {@code serviceAccountKeyJson} (object)
 * or {@code serviceAccountKeyJsonBase64} (string) for explicit service-account auth.
 * Omit both to fall back to application-default credentials / GKE workload identity.
 *
 * <p>Project ID, region, and target identifiers live in {@code configJson}, not here.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class GcpCertificateManagerDeploymentCredJson implements CredJsonPayload {
    private JsonNode serviceAccountKeyJson;
    private String serviceAccountKeyJsonBase64;
}
