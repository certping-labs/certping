// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.digicert;

import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/**
 * The CertCentral API key from a DigiCert CA credential secret: the server writes {@code {"apiKey":"..."}};
 * a bare key, as a customer may keep in their own Key Vault, is read as is.
 */
final class DigiCertApiKey {

    private static final ObjectMapper JSON = JsonMapper.builderWithJackson2Defaults().build();

    private DigiCertApiKey() {
    }

    static String from(String secret) {
        String value = secret == null ? "" : secret.trim();
        if (value.startsWith("{")) {
            value = apiKeyField(value);
        }
        if (value.isEmpty()) {
            throw new PermanentAgentException("MISSING_CA_CREDENTIAL", "The DigiCert CA credential has no API key");
        }
        return value;
    }

    private static String apiKeyField(String json) {
        try {
            JsonNode key = JSON.readTree(json).path("apiKey");
            return key.isString() ? key.asString().trim() : "";
        } catch (Exception e) {
            throw new PermanentAgentException("CA_CREDENTIAL_INVALID", "The DigiCert CA credential is not valid JSON");
        }
    }
}
