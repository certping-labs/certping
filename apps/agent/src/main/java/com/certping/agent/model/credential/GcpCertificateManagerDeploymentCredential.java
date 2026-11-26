// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.credential;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import tools.jackson.databind.JsonNode;
import lombok.Data;

/**
 * GCP KV secret payload — sensitive auth only (Service Account JSON or empty for Workload Identity).
 *
 * <p>All non-sensitive GCP config (projectId, location, allowed-* lists, certificate map names,
 * target proxies) lives in {@code credentialScopeJson} (scope) and {@code targetsJson} (per-cert plan).
 *
 * <p>{@code serviceAccountKeyJson} is typed as {@link JsonNode} so the KV secret can carry it as a
 * nested JSON object (the natural shape — same as the file Google gives you when you download a
 * service-account key). It can also be a JSON string (stringified service-account JSON) — both shapes
 * are accepted. {@link com.certping.agent.deployment.adapter.gcp.GcpScopeSupport#parseKvSecret}
 * normalizes either form into the JSON-string bytes that {@code GoogleCredentials.fromStream} expects.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class GcpCertificateManagerDeploymentCredential {
    private JsonNode serviceAccountKeyJson;
    private String serviceAccountKeyJsonBase64;
}
