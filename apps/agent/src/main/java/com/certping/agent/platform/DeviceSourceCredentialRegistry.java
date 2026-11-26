// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.DevicePlatformType;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Holds sensitive per-profile credentials that must never enter safe profile metadata. */
@Component
public class DeviceSourceCredentialRegistry {
    static final int MAX_CREDENTIALS_JSON_CHARACTERS = 16_384;
    private static final List<String> INTUNE_REQUIRED_FIELDS = List.of(
            "tenantId", "clientId", "clientSecret");
    private static final Set<String> INTUNE_ALLOWED_FIELDS = Set.copyOf(INTUNE_REQUIRED_FIELDS);

    private final DeviceSourceProperties properties;
    private final ObjectMapper objectMapper;
    private final DeviceSourceProfileRegistry profileRegistry;
    private Map<String, String> credentialsJsonByProfileRef = Map.of();

    public DeviceSourceCredentialRegistry(
            DeviceSourceProperties properties,
            ObjectMapper objectMapper,
            DeviceSourceProfileRegistry profileRegistry) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.profileRegistry = profileRegistry;
    }

    @PostConstruct
    void validateCredentials() {
        Map<String, String> validated = new LinkedHashMap<>();
        for (DeviceSourceProperties.Profile candidate : properties.getProfiles()) {
            String profileRef = candidate.getProfileRef() == null
                    ? null : candidate.getProfileRef().trim();
            DevicePlatformType provider = DevicePlatformType.fromString(candidate.getProvider());
            DeviceSourceProfile profile = profileRegistry.require(profileRef, provider);
            validated.put(profile.profileRef(), validateCredentials(candidate, profile));
        }
        credentialsJsonByProfileRef = Collections.unmodifiableMap(
                new LinkedHashMap<>(validated));
    }

    public String requireCredentialsJson(
            String profileRef, DevicePlatformType expectedProvider) {
        profileRegistry.require(profileRef, expectedProvider);
        String credentialsJson = credentialsJsonByProfileRef.get(profileRef);
        if (credentialsJson == null) {
            throw new PermanentAgentException("PLATFORM_NOT_CONFIGURED",
                    "No local credentials are configured for device-source profile " + profileRef);
        }
        return credentialsJson;
    }

    private String validateCredentials(
            DeviceSourceProperties.Profile candidate, DeviceSourceProfile profile) {
        String credentialsJson = required(
                candidate.getCredentialsJson(), profile.profileRef());
        if (credentialsJson.length() > MAX_CREDENTIALS_JSON_CHARACTERS) {
            throw configurationError(profile.profileRef(),
                    "credentials-json exceeds " + MAX_CREDENTIALS_JSON_CHARACTERS + " characters");
        }
        JsonNode credentials = parseCredentials(credentialsJson, profile.profileRef());
        if (!credentials.isObject()) {
            throw configurationError(profile.profileRef(), "credentials-json must be a JSON object");
        }
        if (profile.provider() == DevicePlatformType.INTUNE) {
            validateIntuneCredentials(credentials, profile.profileRef());
        }
        return credentialsJson;
    }

    private JsonNode parseCredentials(String credentialsJson, String profileRef) {
        try {
            return objectMapper.readTree(credentialsJson);
        } catch (JacksonException exception) {
            throw configurationError(profileRef, "credentials-json is not valid JSON");
        }
    }

    private static void validateIntuneCredentials(JsonNode credentials, String profileRef) {
        for (String field : INTUNE_REQUIRED_FIELDS) {
            JsonNode value = credentials.get(field);
            if (value == null || !value.isString() || value.stringValue().isBlank()) {
                throw configurationError(profileRef,
                        "Intune credentials-json must contain a non-empty " + field);
            }
        }
        credentials.propertyNames().iterator().forEachRemaining(field -> {
            if (!INTUNE_ALLOWED_FIELDS.contains(field)) {
                throw configurationError(profileRef,
                        "Intune credentials-json contains unsupported field " + field);
            }
        });
    }

    private static String required(String value, String profileRef) {
        if (value == null || value.isBlank()) {
            throw configurationError(profileRef, "credentials-json is required");
        }
        return value.trim();
    }

    private static IllegalStateException configurationError(
            String profileRef, String message) {
        return new IllegalStateException(
                "Invalid device-source profile " + profileRef + ": " + message);
    }

}
