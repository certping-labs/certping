// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.platform.DeviceSourceProfile;
import com.certping.agent.platform.DeviceSourceProfileRegistry;
import com.certping.agent.scep.ca.ScepCaBackend;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves an {@code endpointId} to its {@link ResolvedEndpoint}. Registers one endpoint per
 * enabled Intune device-source profile, keyed by the source's {@code profileRef} — one stable SCEP
 * URL per Intune connection, never per certificate profile. Adding another Mac/Windows/VPN
 * certificate profile to a connection therefore needs no new route, environment variable, or
 * restart.
 *
 * <p>The {@code default} compatibility alias is created only when it can resolve
 * deterministically: exactly one eligible Intune source. With several sources the alias would have
 * to guess which tenant credential validates a challenge — trying them all is slow, ambiguous, and
 * a tenant-discovery oracle — so it fails closed instead ({@link UnknownEndpointException}).
 */
@Slf4j
@RequiredArgsConstructor
public class ScepEndpointRegistry {

    static final String DEFAULT_ALIAS = "default";

    private final AgentProperties properties;
    private final ScepCaBackend caBackend;
    private final DeviceSourceProfileRegistry sourceRegistry;
    private final Map<String, ResolvedEndpoint> endpoints = new ConcurrentHashMap<>();

    @PostConstruct
    void bootstrap() {
        AgentProperties.ScepProperties scep = properties.getScep();
        List<DeviceSourceProfile> eligible = sourceRegistry.all().stream()
                .filter(source -> source.provider() == DevicePlatformType.INTUNE)
                .toList();

        for (DeviceSourceProfile source : eligible) {
            ResolvedEndpoint endpoint = endpoint(source.profileRef(), source, scep);
            endpoints.put(endpoint.endpointId(), endpoint);
            log.info("SCEP endpoint registered: /scep/v1/{} source={} backend={} caps={}",
                    endpoint.endpointId(), source.profileRef(), scep.getCa().getBackend(), scep.getCaps());
        }

        if (eligible.isEmpty()) {
            log.warn("SCEP is enabled but no Intune device-source profile is configured — "
                    + "no SCEP endpoint is registered and every request will be rejected");
            return;
        }
        registerDefaultAlias(scep, eligible);
    }

    private void registerDefaultAlias(AgentProperties.ScepProperties scep,
                                      List<DeviceSourceProfile> eligible) {
        if (!scep.isDefaultCompatibilityAlias() || endpoints.containsKey(DEFAULT_ALIAS)) {
            return;
        }
        if (eligible.size() > 1) {
            log.warn("SCEP '/scep/v1/default' alias not created: {} eligible Intune sources exist, "
                    + "so the alias cannot resolve deterministically and requests to it will be "
                    + "rejected. Bind each Intune certificate profile to its source URL instead.",
                    eligible.size());
            return;
        }
        DeviceSourceProfile source = eligible.get(0);
        endpoints.put(DEFAULT_ALIAS, endpoint(DEFAULT_ALIAS, source, scep));
        log.info("SCEP compatibility alias registered: /scep/v1/default -> source={} "
                + "(migrate existing Intune profiles to /scep/v1/{})", source.profileRef(), source.profileRef());
    }

    private ResolvedEndpoint endpoint(String endpointId, DeviceSourceProfile source,
                                      AgentProperties.ScepProperties scep) {
        return new ResolvedEndpoint(endpointId, properties.getOrganizationId(),
                source.profileRef(), source.provider(), List.copyOf(scep.getCaps()), caBackend);
    }

    public ResolvedEndpoint resolve(String endpointId) {
        ResolvedEndpoint endpoint = endpoints.get(endpointId);
        if (endpoint == null) {
            throw new UnknownEndpointException(endpointId);
        }
        return endpoint;
    }
}
