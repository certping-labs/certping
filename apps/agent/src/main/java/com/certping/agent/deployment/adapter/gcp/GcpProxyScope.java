// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * {@code credentialScopeJson} for {@code GCP_ALB} / {@code GCP_API_GW} / {@code GCP_CLOUD_CDN} / {@code GCP_PROXY_NLB}.
 *
 * <p>One credential = one proxy. The proxy name lives in scope. Per-cert targets are
 * empty ({@code {}}). The certificate resource base name is auto-derived per-cert from
 * the cert's domain + xref by the adapter.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GcpProxyScope(
        String authMode,
        String projectId,
        String location,
        String impersonateServiceAccount,
        /** For HTTPS proxies (ALB/API GW/CDN). */
        String targetProxy,
        /** For SSL proxies (Proxy NLB). */
        String targetSslProxy) {}
