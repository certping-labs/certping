// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.cloud.gcp;

/**
 * GCP credential scope — fields parsed from {@code credentialScopeJson} on the wire.
 *
 * @param projectId required for adapters that target project-scoped resources
 * @param location  required for resources scoped to a region/zone (e.g. "global", "us-central1")
 * @param impersonateServiceAccount optional — base credentials are impersonated to this SA
 */
public record GcpAuthScope(String projectId, String location, String impersonateServiceAccount) {}
