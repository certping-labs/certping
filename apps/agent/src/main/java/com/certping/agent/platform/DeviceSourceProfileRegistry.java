// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.DevicePlatformType;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

@Component
public class DeviceSourceProfileRegistry {
    private static final Pattern PROFILE_REF = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,99}");
    private static final Set<String> SOURCE_CATEGORIES = Set.of(
            "ENDPOINT_MANAGEMENT", "IOT_REGISTRY", "MANUAL");

    private final DeviceSourceProperties properties;
    private Map<String, DeviceSourceProfile> profiles = Map.of();

    public DeviceSourceProfileRegistry(DeviceSourceProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    void validateProfiles() {
        Map<String, DeviceSourceProfile> validated = new LinkedHashMap<>();
        for (DeviceSourceProperties.Profile candidate : properties.getProfiles()) {
            DeviceSourceProfile profile = validate(candidate);
            if (validated.putIfAbsent(profile.profileRef(), profile) != null) {
                throw new IllegalStateException(
                        "Duplicate agent.device-sources profile-ref: " + profile.profileRef());
            }
        }
        profiles = Collections.unmodifiableMap(new LinkedHashMap<>(validated));
    }

    public List<DeviceSourceProfile> all() {
        return List.copyOf(profiles.values());
    }

    public DeviceSourceProfile require(String profileRef, DevicePlatformType expectedProvider) {
        DeviceSourceProfile profile = profiles.get(profileRef);
        if (profile == null) {
            throw new PermanentAgentException("PLATFORM_NOT_CONFIGURED",
                    "No local device-source profile named " + profileRef);
        }
        if (expectedProvider == null || profile.provider() != expectedProvider) {
            throw new PermanentAgentException("PLATFORM_PROFILE_MISMATCH",
                    "Sync provider does not match local profile " + profileRef);
        }
        return profile;
    }

    private static DeviceSourceProfile validate(DeviceSourceProperties.Profile candidate) {
        String profileRef = required(candidate.getProfileRef(), "profile-ref");
        if (!PROFILE_REF.matcher(profileRef).matches()) {
            throw new IllegalStateException("Invalid device-source profile-ref: " + profileRef);
        }
        DevicePlatformType provider = DevicePlatformType.fromString(candidate.getProvider());
        if (provider == null) {
            throw new IllegalStateException("Unsupported provider for profile " + profileRef);
        }
        String category = required(candidate.getSourceCategory(), "source-category").toUpperCase();
        if (!SOURCE_CATEGORIES.contains(category)) {
            throw new IllegalStateException("Unsupported source-category for profile " + profileRef);
        }
        String displayName = required(candidate.getDisplayName(), "display-name");
        if (displayName.length() > 200) {
            throw new IllegalStateException("display-name exceeds 200 characters for profile " + profileRef);
        }
        String description = trim(candidate.getDescription());
        if (description != null && description.length() > 500) {
            throw new IllegalStateException("description exceeds 500 characters for profile " + profileRef);
        }
        Map<String, Object> metadata = metadata(candidate.getMetadata(), profileRef, provider);
        return new DeviceSourceProfile(
                profileRef, provider, category, displayName, description, metadata);
    }

    private static Map<String, Object> metadata(DeviceSourceProperties.Metadata source,
                                                String profileRef,
                                                DevicePlatformType provider) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (source != null) {
            putMetadata(result, "apiHost", source.getApiHost(), profileRef);
            putMetadata(result, "cloud", source.getCloud(), profileRef);
            putMetadata(result, "environment", source.getEnvironment(), profileRef);
            putMetadata(result, "organizationLabel", source.getOrganizationLabel(), profileRef);
            putMetadata(result, "region", source.getRegion(), profileRef);
            putMetadata(result, "tenantLabel", source.getTenantLabel(), profileRef);
            putMetadata(result, "workspaceLabel", source.getWorkspaceLabel(), profileRef);
        }
        if (provider == DevicePlatformType.INTUNE) {
            validatePublicIntuneEndpoint(result, profileRef);
            result.put("apiHost", "graph.microsoft.com");
            result.put("cloud", "AZURE_PUBLIC");
        }
        return Collections.unmodifiableMap(result);
    }

    private static void validatePublicIntuneEndpoint(Map<String, Object> metadata, String profileRef) {
        Object apiHost = metadata.get("apiHost");
        if (apiHost != null && !"graph.microsoft.com".equalsIgnoreCase(apiHost.toString())) {
            throw new IllegalStateException(
                    "Intune profile " + profileRef + " must use api-host graph.microsoft.com");
        }
        Object cloud = metadata.get("cloud");
        if (cloud != null && !"public".equalsIgnoreCase(cloud.toString())
                && !"azure_public".equalsIgnoreCase(cloud.toString())) {
            throw new IllegalStateException(
                    "Intune profile " + profileRef + " must use cloud AZURE_PUBLIC");
        }
    }

    private static void putMetadata(Map<String, Object> target,
                                    String key,
                                    String value,
                                    String profileRef) {
        String normalized = trim(value);
        if (normalized == null) {
            return;
        }
        if (normalized.length() > 500) {
            throw new IllegalStateException(
                    "metadata " + key + " exceeds 500 characters for profile " + profileRef);
        }
        target.put(key, normalized);
    }

    private static String required(String value, String field) {
        String trimmed = trim(value);
        if (trimmed == null) {
            throw new IllegalStateException("agent.device-sources " + field + " is required");
        }
        return trimmed;
    }

    private static String trim(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }
}
