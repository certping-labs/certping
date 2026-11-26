// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "agent.device-sources")
public class DeviceSourceProperties {
    public static final int MIN_RESPONSE_BYTES = 1_024;
    public static final int MAX_RESPONSE_BYTES = 240 * 1_024;

    private Duration healthInterval = Duration.ofMinutes(5);
    private Duration healthInitialDelay = Duration.ofSeconds(15);
    /** Serialized response-part ceiling; keeps each response message small. */
    private int maxResponseBytes = 240 * 1024;
    private List<Profile> profiles = new ArrayList<>();

    @PostConstruct
    void validate() {
        if (maxResponseBytes < MIN_RESPONSE_BYTES || maxResponseBytes > MAX_RESPONSE_BYTES) {
            throw new IllegalStateException("agent.device-sources.max-response-bytes must be between "
                    + MIN_RESPONSE_BYTES + " and " + MAX_RESPONSE_BYTES);
        }
    }

    @Getter
    @Setter
    public static class Profile {
        private String profileRef;
        private String provider;
        private String sourceCategory = "ENDPOINT_MANAGEMENT";
        private String displayName;
        private String description;
        private String credentialsJson;
        private Metadata metadata = new Metadata();
    }

    /**
     * Safe, provider-neutral labels that help users distinguish multiple source
     * connections. Keeping these fields explicit also makes indexed environment
     * variable binding reliable and prevents arbitrary configuration from being
     * advertised to the server.
     */
    @Getter
    @Setter
    public static class Metadata {
        private String apiHost;
        private String cloud;
        private String environment;
        private String organizationLabel;
        private String region;
        private String tenantLabel;
        private String workspaceLabel;
    }
}
