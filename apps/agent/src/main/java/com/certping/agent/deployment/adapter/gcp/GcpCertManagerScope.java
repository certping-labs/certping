// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * {@code credentialScopeJson} for {@code GCP_CERT_MANAGER}.
 *
 * <p>One credential = one GCP project + (optionally) one Certificate Map. Per-cert CN+SAN
 * list at deploy time drives which {@code CertificateMapEntry} resources are bound — the
 * adapter looks up existing entries by hostname, updates those, and creates new entries for
 * any uncovered hostnames. So no per-hostname operator config is needed.
 *
 * <p>{@code certificateMap} is optional: when blank, the adapter only uploads the cert
 * resource and returns its name (operator binds it via target proxy / LB SSL config
 * out-of-band).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GcpCertManagerScope(
        String authMode,
        String projectId,
        String location,
        String impersonateServiceAccount,
        String certificateMap) {}
