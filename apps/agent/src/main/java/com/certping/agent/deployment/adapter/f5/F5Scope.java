// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.f5;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Parsed shape of {@code credentialScopeJson} for {@code F5_BIGIP}.
 *
 * <p>One credential = one BIG-IP partition. Auth is always BASIC_AUTH (username + password
 * from the KV secret). The per-cert F5 object base name lives in {@link F5Targets} so one
 * partition can host many independent certs.
 *
 * @param bigipHost          required — management hostname/IP
 * @param bigipPort          optional — defaults to 443
 * @param verifySsl          optional — defaults to true; set false only for self-signed mgmt certs
 * @param partition          required — BIG-IP partition (e.g. Common)
 * @param clientSslProfiles  optional — bootstrap anchor list for the first deploy
 * @param installOnly        optional — defaults to false; if true, install cert/key without binding
 * @param deviceGroup        optional — explicit HA Sync-Failover group; auto-detected if absent
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record F5Scope(
        String bigipHost,
        Integer bigipPort,
        Boolean verifySsl,
        String partition,
        List<String> clientSslProfiles,
        Boolean installOnly,
        String deviceGroup) {}
