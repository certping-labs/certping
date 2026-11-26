// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

/**
 * Supported certificate deployment target types.
 *
 * <p>
 * Values MUST match the {@code TargetType} enum in certping-agent exactly,
 * because
 * Jackson serialises this as a bare string (e.g. {@code "AZURE_KV"}) when
 * building the
 * {@link CertDeploymentCommand}, and the agent deserialises the same string
 * back into its
 * own {@code TargetType} enum. Any value added here must also be added to the
 * agent's enum.
 *
 * <p>
 * Credential provider values in {@code credential_references.provider} must
 * also match
 * these names so that the deployment credential provider-vs-targetType
 * validation holds.
 */
public enum TargetType {

    /**
     * Import certificate into an Azure Key Vault. Requires
     * {@code deployToVaultUri}.
     */
    AZURE_KV,

    /** Import certificate into AWS Certificate Manager (ACM). */
    AWS_ACM,

    /** Update Azure Application Gateway SSL certificate. */
    AZURE_APP_GW,

    /** Update Azure Application Gateway for Containers SSL certificate. */
    AZURE_APP_GW_CONTAINERS,

    /**
     * Update Azure Front Door (Standard/Premium) custom domain TLS certificate via
     * Key Vault.
     */
    AZURE_AFD,

    /** Update AWS Application Load Balancer listener certificates. */
    AWS_ALB,

    /** Update AWS Network Load Balancer listener certificates. */
    AWS_NLB,

    /** Update AWS API Gateway REST (v1) custom domain. */
    AWS_API_GW_REST,

    /** Update AWS API Gateway HTTP/WebSocket (v2) custom domain. */
    AWS_API_GW_HTTP,

    /** Update AWS CloudFront distribution certificate. */
    AWS_CLOUDFRONT,

    /**
     * Discovery only: scan every account and region in an AWS Organization for ACM
     * certificates. Never a deployment target.
     */
    AWS_ORGANIZATION,

    /** GCP Certificate Manager upload (BYO PEM). */
    GCP_CERT_MANAGER,

    /** GCP Application Load Balancer — Target HTTPS Proxy. */
    GCP_ALB,

    /** GCP Proxy Network Load Balancer — Target SSL Proxy. */
    GCP_PROXY_NLB,

    /** GCP API Gateway custom domain (HTTPS LB + Serverless NEG) — same TLS path as {@link #GCP_ALB}. */
    GCP_API_GW,

    /**
     * GCP Cloud CDN — caching on an ALB backend; TLS remains on the same Target HTTPS Proxy as {@link #GCP_ALB}.
     * Reuses the ALB deployment credential and adapter.
     */
    GCP_CLOUD_CDN,

    /** Update Cloudflare CDN Edge (Custom SSL) certificate. */
    CLOUDFLARE_EDGE,

    /** Deploy certificate as kubernetes.io/tls Secret to Kubernetes cluster(s). */
    KUBERNETES_SECRETS,

    /** Update Akamai CPS (third-party enrollment) certificate. */
    AKAMAI_CPS,

    /** Update F5 BIG-IP Client SSL profile via iControl REST. */
    F5_BIGIP;
}
