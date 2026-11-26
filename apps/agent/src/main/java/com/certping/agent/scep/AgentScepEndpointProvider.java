// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.platform.DeviceSourceProfile;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

/**
 * Supplies the public SCEP URLs advertised for one device source:
 * {@code <publicBaseUrl>/scep/v1/<connectionProfileRef>}. Every certificate profile created
 * through the same source receives the same URL, so creating another certificate profile never
 * registers a new endpoint — source configuration owns the endpoint lifecycle.
 */
@Component
@RequiredArgsConstructor
public class AgentScepEndpointProvider {

    private final AgentProperties properties;

    public List<String> requireAdvertisedUrls(DeviceSourceProfile source) {
        if (source == null) {
            throw new PermanentAgentException("SCEP_ENDPOINT_NOT_CONFIGURED",
                    "A device source is required to advertise a SCEP URL");
        }
        return List.of(requireAdvertisedUrl(source.profileRef()));
    }

    /** The public URL of one SCEP route, including the {@code default} compatibility alias. */
    public String requireAdvertisedUrl(String endpointId) {
        AgentProperties.ScepProperties scep = properties.getScep();
        if (!scep.isEnabled()) {
            throw new PermanentAgentException("SCEP_ENDPOINT_NOT_CONFIGURED",
                    "The agent SCEP listener is not enabled (agent.scep.enabled)");
        }
        String baseUrl = scep.getPublicBaseUrl();
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new PermanentAgentException("SCEP_ENDPOINT_NOT_CONFIGURED",
                    "agent.scep.public-base-url is not configured, so no SCEP URL can be advertised");
        }
        String normalized = baseUrl.trim();
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        validateBaseUrl(normalized);
        return normalized + "/scep/v1/" + endpointId;
    }

    /**
     * This value is pushed verbatim into every Intune certificate profile, so a malformed one
     * breaks device enrollment fleet-wide. HTTPS is required except for loopback dev hosts.
     */
    private static void validateBaseUrl(String baseUrl) {
        if (baseUrl.length() > 255) {
            throw new PermanentAgentException("SCEP_ENDPOINT_NOT_CONFIGURED",
                    "agent.scep.public-base-url exceeds 255 characters");
        }
        URI uri;
        try {
            uri = new URI(baseUrl);
        } catch (URISyntaxException e) {
            throw new PermanentAgentException("SCEP_ENDPOINT_NOT_CONFIGURED",
                    "agent.scep.public-base-url is not a valid URL");
        }
        String host = uri.getHost();
        boolean loopback = "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host);
        boolean https = "https".equalsIgnoreCase(uri.getScheme());
        boolean http = "http".equalsIgnoreCase(uri.getScheme());
        if (host == null || !(https || (http && loopback))
                || uri.getQuery() != null || uri.getFragment() != null) {
            throw new PermanentAgentException("SCEP_ENDPOINT_NOT_CONFIGURED",
                    "agent.scep.public-base-url must be an absolute https URL "
                            + "(http is allowed for localhost only) without query or fragment");
        }
    }
}
