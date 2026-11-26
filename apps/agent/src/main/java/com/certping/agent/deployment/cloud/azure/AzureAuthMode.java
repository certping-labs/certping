// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.cloud.azure;

/** Azure auth mode declared in {@code credential_references.config.authMode}. */
public enum AzureAuthMode {
    /** Service principal — clientId + clientSecret in KV secret. */
    SERVICE_PRINCIPAL,
    /** Federated workload identity — clientId in scope, federated token from environment. No KV secret. */
    WORKLOAD_IDENTITY
}
