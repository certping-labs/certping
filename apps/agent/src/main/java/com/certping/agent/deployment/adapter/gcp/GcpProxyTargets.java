// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * {@code targetsJson} for GCP proxy adapters (ALB/APIGW/CDN/NLB).
 *
 * <p>All configuration (proxy name, certificate base name) is in the credential scope.
 * Targets are empty ({@code {}}) — provided for envelope consistency but carry no fields.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GcpProxyTargets() {}
