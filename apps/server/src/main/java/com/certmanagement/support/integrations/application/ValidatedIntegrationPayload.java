// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.application;

import java.util.Map;

record ValidatedIntegrationPayload(
        Map<String, Object> config,
        Map<String, String> secrets
) {
}
