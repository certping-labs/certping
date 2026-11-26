// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.entity.Organization;
import com.certmanagement.repository.OrganizationRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Single-purpose lookup for an organization's {@code orgType}. Every organization is {@code B2B}; the
 * value stays on agent commands because the agent's message contract carries it.
 *
 * <p>Used by callers that need to populate the {@code orgType} field on outbound
 * {@code *Command} DTOs before handing them to {@link com.certmanagement.messaging.CertAgentPublisher}.
 * The publisher itself does not call this — it reads {@code orgType} from the payload — so the
 * messaging layer has no dependency on the repository.
 *
 * <p>Lazily populated, never invalidated within the pod's lifetime. Org type rarely changes; if
 * it ever does, a pod restart will pick up the new value.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OrgTypeResolver {

    private final OrganizationRepository organizationRepository;
    private final Map<Long, String> cache = new ConcurrentHashMap<>();

    /**
     * Returns the {@code orgType} for the given org. Throws {@link IllegalStateException} when
     * the org is unknown — callers must not silently fall back to a default, because routing
     * is driven by this value and getting it wrong silently misroutes commands.
     */
    public String resolve(Long organizationId) {
        if (organizationId == null) {
            throw new IllegalArgumentException("organizationId must not be null when resolving orgType");
        }
        return cache.computeIfAbsent(organizationId, id ->
                organizationRepository.findById(id)
                        .map(Organization::getOrgType)
                        .orElseThrow(() -> new IllegalStateException(
                                "Unknown organizationId=" + id + " — cannot resolve orgType")));
    }

    /** Convenience overload — accepts the numeric id as a String. */
    public String resolve(String organizationId) {
        try {
            return resolve(Long.parseLong(organizationId));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "organizationId must be a numeric id, got '" + organizationId + "'", e);
        }
    }

    public Map<Long, String> resolveAll(Collection<Long> organizationIds) {
        if (organizationIds == null || organizationIds.isEmpty()) {
            return Map.of();
        }
        Set<Long> missing = organizationIds.stream()
                .filter(id -> id != null && !cache.containsKey(id))
                .collect(Collectors.toSet());
        if (!missing.isEmpty()) {
            organizationRepository.findAllById(missing)
                    .forEach(organization -> cache.put(
                            organization.getId(), organization.getOrgType()));
            missing.removeAll(cache.keySet());
            if (!missing.isEmpty()) {
                throw new IllegalStateException(
                        "Unknown organizationIds=" + missing + " — cannot resolve orgType");
            }
        }
        return organizationIds.stream().distinct().collect(Collectors.toUnmodifiableMap(
                id -> id, cache::get));
    }

    /** Test hook — drops cached entries (e.g. between integration test cases). */
    public void invalidateAll() {
        cache.clear();
    }
}
