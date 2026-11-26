// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * {@code targetsJson} for {@code AZURE_KV} — flat, just the certificate name.
 *
 * <p>The vault URI is in the credential scope ({@link AzureKvScope#vaultUri()}),
 * so targets only need to declare where inside that vault the cert should live.
 *
 * @param certificateName optional — Azure KV certificate name (1-127 alphanumeric/hyphen).
 *                        Targets-first precedence: when set, always wins (supports rename).
 *                        When blank, the adapter falls back to {@code result.certificateName}
 *                        (renewal stability), then auto-derives from the cert's primary domain.
 *                        Renaming via this field creates a new KV cert under the new name; the
 *                        old KV cert keeps existing under its old name (operator purges manually).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AzureKvTargets(String certificateName) {}
