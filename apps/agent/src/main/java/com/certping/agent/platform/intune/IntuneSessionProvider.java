// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.platform.DeviceSourceCredentialRegistry;
import com.certping.agent.platform.DeviceSourceProfile;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import java.util.Map;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class IntuneSessionProvider {
    private final IntuneGraphClient graphClient;
    private final DeviceSourceCredentialRegistry credentialRegistry;
    private final ObjectMapper objectMapper;

    public IntuneSession open(DeviceSourceProfile profile) {
        Map<String, Object> credentials = readCredentials(profile);
        String tenantId = string(credentials.get("tenantId"));
        String clientId = string(credentials.get("clientId"));
        String clientSecret = string(credentials.get("clientSecret"));
        if (tenantId == null || clientId == null || clientSecret == null) {
            throw new PermanentAgentException("PLATFORM_NOT_CONFIGURED",
                    "Intune credentials must contain tenantId, clientId and clientSecret");
        }
        String token = graphClient.acquireToken(tenantId, clientId, clientSecret);
        return new IntuneSession(token, tokenRoles(token));
    }

    private Map<String, Object> readCredentials(DeviceSourceProfile profile) {
        try {
            String credentialsJson = credentialRegistry.requireCredentialsJson(
                    profile.profileRef(), profile.provider());
            return objectMapper.readValue(credentialsJson, new TypeReference<>() {});
        } catch (Exception exception) {
            if (exception instanceof PermanentAgentException permanentAgentException) {
                throw permanentAgentException;
            }
            throw new PermanentAgentException("PLATFORM_NOT_CONFIGURED",
                    "Could not read Intune credentials from agent configuration");
        }
    }

    private static String string(Object value) {
        if (value == null || value.toString().isBlank()) {
            return null;
        }
        return value.toString().trim();
    }

    private Set<String> tokenRoles(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                throw new IllegalArgumentException("token has no claims segment");
            }
            JsonNode payload = objectMapper.readTree(
                    Base64.getUrlDecoder().decode(parts[1]));
            JsonNode roles = payload.path("roles");
            if (!roles.isArray()) {
                return Set.of();
            }
            Set<String> values = new LinkedHashSet<>();
            roles.forEach(role -> {
                if (role.isString() && !role.stringValue().isBlank()) {
                    values.add(role.stringValue());
                }
            });
            return Set.copyOf(values);
        } catch (RuntimeException  exception) {
            throw new PermanentAgentException(
                    "PLATFORM_AUTH_INVALID", "Microsoft Graph returned an invalid access token");
        }
    }
}
