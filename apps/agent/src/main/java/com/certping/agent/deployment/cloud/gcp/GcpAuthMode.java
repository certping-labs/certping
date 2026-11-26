// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.cloud.gcp;

/** GCP auth mode declared in {@code credential_references.config.authMode}. */
public enum GcpAuthMode {
    /** Service account JSON key in KV secret. */
    SERVICE_ACCOUNT_KEY,
    /** GKE Workload Identity / Application Default Credentials. No KV secret. */
    WORKLOAD_IDENTITY
}
