// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.discovery;

record DiscoveryBatchContext(
        boolean tracked,
        boolean duplicate,
        String scopeKey,
        String credentialXref) {

    static DiscoveryBatchContext untracked() {
        return new DiscoveryBatchContext(false, false, null, null);
    }
}
