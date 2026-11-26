// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * {@code targetsJson} for {@code GCP_CERT_MANAGER}.
 *
 * @param certificateName  optional — exact GCP Certificate resource id.
 *                         Targets-first precedence: when set, always wins. If it differs
 *                         from the prior resource's id, the agent treats it as a rename —
 *                         creates a new Certificate resource at the new id, reconciles map
 *                         entries to point at it, deletes the old resource (best-effort) after
 *                         repointing. When blank, falls back to in-place updating the prior
 *                         resource (renewal stability), then to an auto-derived versioned id
 *                         {@code {domain-normalized}-{xref-suffix}-{yyyyMMddHHmmss}} on first
 *                         deploy. SAN-change rotation without operator name uses the same
 *                         versioned suffix to avoid colliding with the still-existing prior.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GcpCertManagerTargets(String certificateName) {}
