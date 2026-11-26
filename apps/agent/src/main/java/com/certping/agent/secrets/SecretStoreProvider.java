// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.secrets;

public enum SecretStoreProvider {
    AZURE_KV,
    AWS_SECRETS_MANAGER,
    GCP_SECRET_MANAGER,
    /** Encrypted files on a volume shared with the server. Single-server installs only. */
    LOCAL
}
