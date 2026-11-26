// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.f5;

import java.util.List;

/**
 * Per-deployment internal config passed to {@link F5BigIpCertRotator}. Built once per deploy
 * by the adapter (one partition per credential).
 *
 * @param newCertHostnames  CN + SANs of the cert being deployed (literal, including wildcards).
 *                          Used by the rotator's third-tier bootstrap fallback to discover
 *                          existing client-SSL profiles whose bound cert overlaps with this
 *                          cert's identity — only consulted on first deploy when neither
 *                          {@code clientSslProfiles} nor a prior cert ref is available.
 */
record F5BigIpConfig(
        String bigipHost,
        int bigipPort,
        String username,
        String password,
        String partition,
        String certName,
        String keyName,
        List<String> clientSslProfiles,
        boolean installOnly,
        boolean verifySsl,
        List<String> newCertHostnames
) {
}
