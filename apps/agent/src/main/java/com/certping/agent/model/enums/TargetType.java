// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.enums;

public enum TargetType {
    AZURE_KV,
    AWS_ACM,
    AZURE_APP_GW,
    AZURE_APP_GW_CONTAINERS,
    AZURE_AFD,
    AWS_ALB,
    AWS_NLB,
    AWS_API_GW_REST,
    AWS_API_GW_HTTP,
    AWS_CLOUDFRONT,
    /** Discovery only: every account and region in an AWS Organization. Never a deployment target. */
    AWS_ORGANIZATION,
    KUBERNETES_SECRETS,
    GCP_CERT_MANAGER,
    GCP_ALB,
    GCP_PROXY_NLB,
    GCP_API_GW,
    /**
     * GCP Cloud CDN — caching on an ALB backend service; TLS stays on the same Target HTTPS Proxy as {@link #GCP_ALB}.
     */
    GCP_CLOUD_CDN,
    CLOUDFLARE_EDGE,
    AKAMAI_CPS,

    /** F5 BIG-IP iControl REST — update client SSL profile cert/key. */
    F5_BIGIP;
}
