// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * One EJBCA connection's credential, parsed from the JSON blob the customer stores in their
 * own secret manager.
 *
 * <p>{@code authMethod} is the only discriminator. EJBCA's REST API accepts exactly two
 * credentials — a client certificate or an OAuth bearer token — and both behave identically
 * on Community and Enterprise, so nothing here varies by edition or version.
 *
 * @param serverCaChainPem PEM chain that signed EJBCA's <em>own TLS certificate</em> (normally
 *                         ManagementCA, which is not publicly trusted). Null means fall back to
 *                         the system trust store. It must never mean "skip verification".
 */
record EjbcaCredentials(
        AuthMethod authMethod,
        String baseUrl,
        // CLIENT_CERT
        String clientP12Base64,
        String clientP12Password,
        // OAUTH_CLIENT_CREDENTIALS
        String tokenUrl,
        String clientId,
        String clientSecret,
        String scope,
        String audience,
        // both
        String serverCaChainPem
) {

    enum AuthMethod { CLIENT_CERT, OAUTH_CLIENT_CREDENTIALS }

    /**
     * Redacted deliberately: the generated record {@code toString()} would print
     * {@code clientP12Password} and {@code clientSecret} in clear, and one stray
     * {@code log.debug("creds={}", credentials)} is all it would take.
     */
    @Override
    public String toString() {
        return "EjbcaCredentials[authMethod=" + authMethod + ", baseUrl=" + baseUrl
                + ", secrets redacted]";
    }

    /**
     * @param baseUrlOverride {@code agent.ejbca.base-url}; wins over the secret's own baseUrl so
     *                        an operator can keep the endpoint visible in the deployment manifest.
     */
    static EjbcaCredentials parse(String rawJson, ObjectMapper mapper, String baseUrlOverride) {
        if (rawJson == null || rawJson.isBlank()) {
            throw new PermanentAgentException("EJBCA_CREDENTIAL_MISSING",
                    "EJBCA credential secret is empty. Check agent.ejbca.credential-path.");
        }

        JsonNode json;
        try {
            json = mapper.readTree(rawJson);
        } catch (Exception e) {
            throw new PermanentAgentException("EJBCA_CREDENTIAL_INVALID",
                    "EJBCA credential secret is not valid JSON: " + e.getMessage(), e);
        }

        String method = text(json, "authMethod");
        if (method == null) {
            throw new PermanentAgentException("EJBCA_CREDENTIAL_INVALID",
                    "EJBCA credential is missing 'authMethod'. Expected CLIENT_CERT or OAUTH_CLIENT_CREDENTIALS.");
        }

        AuthMethod authMethod;
        try {
            authMethod = AuthMethod.valueOf(method.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new PermanentAgentException("EJBCA_CREDENTIAL_INVALID",
                    "Unsupported EJBCA authMethod '" + method
                            + "'. Expected CLIENT_CERT or OAUTH_CLIENT_CREDENTIALS.");
        }

        String baseUrl = notBlank(baseUrlOverride) ? baseUrlOverride.trim() : text(json, "baseUrl");
        require(baseUrl, "baseUrl");
        if (!baseUrl.startsWith("https://")) {
            // Port 8080 always 302-redirects to 8443, and a redirected POST silently loses its body.
            throw new PermanentAgentException("EJBCA_CREDENTIAL_INVALID",
                    "EJBCA baseUrl must be https (got '" + baseUrl + "'). Plain HTTP redirects to 8443.");
        }
        baseUrl = stripTrailingSlash(baseUrl);

        EjbcaCredentials creds = new EjbcaCredentials(
                authMethod,
                baseUrl,
                text(json, "clientP12Base64"),
                // An unprotected P12 legitimately has an empty password, so only null is missing.
                json.hasNonNull("clientP12Password") ? json.get("clientP12Password").asString() : null,
                text(json, "tokenUrl"),
                text(json, "clientId"),
                text(json, "clientSecret"),
                text(json, "scope"),
                text(json, "audience"),
                text(json, "serverCaChainPem"));

        switch (authMethod) {
            case CLIENT_CERT -> {
                require(creds.clientP12Base64(), "clientP12Base64");
                if (creds.clientP12Password() == null) {
                    throw new PermanentAgentException("EJBCA_CREDENTIAL_INVALID",
                            "EJBCA credential is missing 'clientP12Password' "
                                    + "(use \"\" for an unprotected P12).");
                }
            }
            case OAUTH_CLIENT_CREDENTIALS -> {
                require(creds.tokenUrl(), "tokenUrl");
                require(creds.clientId(), "clientId");
                require(creds.clientSecret(), "clientSecret");
            }
        }
        return creds;
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) {
            return null;
        }
        String s = v.asString();
        return s.isBlank() ? null : s;
    }

    private static void require(String value, String field) {
        if (!notBlank(value)) {
            throw new PermanentAgentException("EJBCA_CREDENTIAL_INVALID",
                    "EJBCA credential is missing required field '" + field + "'.");
        }
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }

    private static String stripTrailingSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }
}
