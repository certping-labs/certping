// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.model.message.CertificateCorrelationCandidate;
import com.certping.agent.model.message.CertificateCorrelationResult;
import com.certping.agent.model.message.CertificateProfileMessage;
import com.certping.agent.model.message.ProfileObservedState;
import com.certping.agent.platform.CertificateProfileConnector;
import com.certping.agent.platform.CertificateProfileConnectorFor;
import com.certping.agent.platform.DeviceSourceProfile;
import com.certping.agent.scep.AgentScepEndpointProvider;
import com.certping.agent.scep.ca.ScepCaBackend;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

@Slf4j
@Component
@RequiredArgsConstructor
@CertificateProfileConnectorFor(DevicePlatformType.INTUNE)
public class IntuneCertificateProfileConnector implements CertificateProfileConnector {
    /** One correlation run can issue at most this many managed-state Graph page requests. */
    private static final int MAX_CORRELATION_GRAPH_PAGES = 250;
    private final IntuneSessionProvider sessionProvider;
    private final IntuneCertificateProfileClient client;
    private final IntuneCertificateProfileMapper mapper;
    private final AgentScepEndpointProvider scepEndpointProvider;
    private final ObjectProvider<ScepCaBackend> scepCaBackend;

    @Override
    public ProfileObservedState create(
            DeviceSourceProfile source, CertificateProfileMessage command) {
        Map<String, Object> payload = mapper.toWindowsScepPayload(
                command, scepEndpointProvider.requireAdvertisedUrls(source));
        List<String> groupIds = mapper.assignmentGroupIds(command);
        IntuneSession session = sessionProvider.open(source);
        var existing = client.findByCorrelationMarker(
                session.token(), command.getProviderCorrelationMarker());
        ProfileObservedState observed = existing.isPresent()
                ? requireOwnedProfile(command, existing.get(), null)
                : mapper.fromGraph(client.create(session.token(), payload));
        deploy(session.token(), command, observed.getProviderProfileId(), groupIds);
        return observed;
    }

    @Override
    public ProfileObservedState update(
            DeviceSourceProfile source, CertificateProfileMessage command) {
        Map<String, Object> payload = mapper.toWindowsScepPayload(
                command, scepEndpointProvider.requireAdvertisedUrls(source));
        List<String> groupIds = mapper.assignmentGroupIds(command);
        IntuneSession session = sessionProvider.open(source);
        requireOwnedProfile(command,
                client.get(session.token(), command.getProviderProfileId()),
                command.getProviderProfileId());
        ProfileObservedState observed = mapper.fromGraph(client.update(
                session.token(), command.getProviderProfileId(), payload));
        deploy(session.token(), command, observed.getProviderProfileId(), groupIds);
        return observed;
    }

    /**
     * Intune will not deliver a SCEP profile without a linked trusted root profile, and delivers
     * nothing that is unassigned. Both steps are idempotent so a retried create or update repairs
     * whatever an earlier attempt left half done.
     */
    private void deploy(String token, CertificateProfileMessage command,
                        String scepProfileId, List<String> groupIds) {
        String rootProfileId = ensureTrustedRoot(token, command, scepProfileId);
        if (groupIds == null) {
            return;
        }
        client.assign(token, scepProfileId, groupIds);
        if (rootProfileId != null) {
            client.assign(token, rootProfileId, groupIds);
        }
    }

    private String ensureTrustedRoot(
            String token, CertificateProfileMessage command, String scepProfileId) {
        ScepCaBackend backend = scepCaBackend.getIfAvailable();
        List<X509Certificate> chain = backend == null ? List.of() : backend.getCaChain();
        if (chain.isEmpty()) {
            log.warn("No SCEP CA chain on this agent; Intune profile {} needs a trusted root "
                    + "profile linked by hand before devices will enroll", scepProfileId);
            return null;
        }
        X509Certificate root = chain.get(chain.size() - 1);
        String marker = command.getProviderCorrelationMarker() + ":root";
        Map<String, Object> payload = mapper.toWindowsTrustedRootPayload(command, marker, root);
        var existing = client.findByCorrelationMarker(token, marker);
        String rootProfileId;
        if (existing.isEmpty()) {
            rootProfileId = string(client.create(token, payload).get("id"));
        } else {
            rootProfileId = string(existing.get().get("id"));
            if (!mapper.holdsTrustedRoot(client.get(token, rootProfileId), root)) {
                client.update(token, rootProfileId, payload);
            }
        }
        client.linkWindowsScepRootCertificate(token, scepProfileId, rootProfileId);
        return rootProfileId;
    }

    @Override
    public void streamProfiles(
            DeviceSourceProfile source, Consumer<List<ProfileObservedState>> pageConsumer) {
        IntuneSession session = sessionProvider.open(source);
        client.streamCertificateProfiles(session.token(), rawPage -> {
            List<ProfileObservedState> mappedProfiles = new ArrayList<>(rawPage.size());
            RuntimeException mappingFailure = null;
            for (Map<String, Object> rawProfile : rawPage) {
                try {
                    mappedProfiles.add(mapper.fromGraphForDiscovery(rawProfile));
                } catch (RuntimeException exception) {
                    if (mappingFailure == null) {
                        mappingFailure = exception;
                    }
                }
            }
            if (!mappedProfiles.isEmpty()) {
                pageConsumer.accept(List.copyOf(mappedProfiles));
            }
            if (mappingFailure != null) {
                throw mappingFailure;
            }
        });
    }

    @Override
    public List<CertificateCorrelationResult> correlateCertificates(
            DeviceSourceProfile source, List<CertificateCorrelationCandidate> candidates) {
        if (candidates.isEmpty()) {
            return List.of();
        }
        IntuneCertificateProfileCorrelator correlator =
                new IntuneCertificateProfileCorrelator(candidates);
        IntuneSession session = sessionProvider.open(source);
        int[] remainingPages = {MAX_CORRELATION_GRAPH_PAGES};
        client.streamCertificateProfiles(session.token(), profiles -> {
            for (Map<String, Object> profile : profiles) {
                String id = string(profile.get("id"));
                String type = string(profile.get("@odata.type"));
                if (!isScepProfile(type)) {
                    continue;
                }
                int consumed = client.streamManagedDeviceCertificateStates(
                        session.token(), id, type, remainingPages[0],
                        states -> states.forEach(state -> correlator.accept(id, type, state)));
                remainingPages[0] -= consumed;
            }
        });
        return correlator.results();
    }

    private ProfileObservedState requireOwnedProfile(
            CertificateProfileMessage command,
            Map<String, Object> rawProfile,
            String expectedProviderProfileId) {
        ProfileObservedState observed = mapper.fromGraph(rawProfile);
        boolean expectedType = command.getProviderProfileType() != null
                && command.getProviderProfileType().equalsIgnoreCase(
                observed.getProviderProfileType());
        boolean expectedMarker = Objects.equals(
                command.getProviderCorrelationMarker(),
                observed.getProviderCorrelationMarker());
        boolean expectedId = expectedProviderProfileId == null
                || Objects.equals(expectedProviderProfileId, observed.getProviderProfileId());
        if (!expectedType || !expectedMarker || !expectedId) {
            throw new PermanentAgentException(
                    "PROFILE_OWNERSHIP_CONFLICT",
                    "The native Intune profile does not match the expected CertPing profile");
        }
        return observed;
    }

    private static boolean isScepProfile(String type) {
        return type != null && type.toLowerCase(java.util.Locale.ROOT)
                .contains("scepcertificateprofile");
    }

    private static String string(Object value) {
        return value == null || value.toString().isBlank() ? null : value.toString().trim();
    }
}
