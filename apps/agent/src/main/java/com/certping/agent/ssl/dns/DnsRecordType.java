// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

/**
 * The record types the agent publishes for domain validation: TXT for ACME DNS-01 challenges, CNAME for
 * CSR-hash validation. Each provider's API names them by {@link #name()}.
 */
public enum DnsRecordType {
    TXT,
    CNAME
}
