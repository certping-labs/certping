// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.platform.DeviceSourceProfile;
import com.certping.agent.platform.DeviceSourceProfileRegistry;
import com.certping.agent.scep.AgentScepEndpointProvider;
import com.certping.agent.scep.ResolvedEndpoint;
import com.certping.agent.scep.ScepProfileHintResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Finds the Intune SCEP profiles whose {@code scepServerUrls} name this agent endpoint, so the CA
 * can honour the profile's validity and the issued certificate can carry its Intune profile id.
 * Results are cached per endpoint because every enrollment asks.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class IntuneScepProfileHintResolver implements ScepProfileHintResolver {
    static final Duration CACHE_TTL = Duration.ofMinutes(10);
    static final Duration FAILURE_TTL = Duration.ofMinutes(1);

    private final DeviceSourceProfileRegistry sources;
    private final IntuneSessionProvider sessions;
    private final IntuneCertificateProfileClient client;
    private final AgentScepEndpointProvider endpoints;
    private final Clock clock;
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();

    private record Cached(ScepProfileHint hint, Instant expiresAt) {}

    @Override
    public ScepProfileHint resolve(ResolvedEndpoint endpoint) {
        if (endpoint.provider() != DevicePlatformType.INTUNE) {
            return ScepProfileHint.NONE;
        }
        Instant now = clock.instant();
        Cached cached = cache.get(endpoint.endpointId());
        if (cached != null && now.isBefore(cached.expiresAt())) {
            return cached.hint();
        }
        ScepProfileHint hint;
        Duration ttl = CACHE_TTL;
        try {
            hint = lookup(endpoint);
        } catch (RuntimeException exception) {
            log.warn("Intune SCEP profile lookup failed for endpoint {}; issuing with CA defaults: {}",
                    endpoint.endpointId(), exception.getMessage());
            hint = ScepProfileHint.NONE;
            ttl = FAILURE_TTL;
        }
        cache.put(endpoint.endpointId(), new Cached(hint, now.plus(ttl)));
        return hint;
    }

    private ScepProfileHint lookup(ResolvedEndpoint endpoint) {
        String url = normalizeUrl(endpoints.requireAdvertisedUrl(endpoint.endpointId()));
        DeviceSourceProfile source = sources.require(
                endpoint.connectionProfileRef(), DevicePlatformType.INTUNE);
        String token = sessions.open(source).token();
        List<Map<String, Object>> matches = new ArrayList<>();
        client.streamCertificateProfiles(token, page -> page.stream()
                .filter(profile -> isScepProfile(profile) && pointsAt(profile, url))
                .forEach(matches::add));
        String providerProfileId = matches.size() == 1 ? string(matches.get(0).get("id")) : null;
        List<Duration> validities = matches.stream()
                .map(IntuneScepProfileHintResolver::validity).distinct().toList();
        Duration validity = validities.size() == 1 ? validities.get(0) : null;
        log.info("Intune SCEP profiles for endpoint {}: matches={} validity={}",
                endpoint.endpointId(), matches.size(), validity);
        return new ScepProfileHint(providerProfileId, validity);
    }

    static Duration validity(Map<String, Object> profile) {
        if (!(profile.get("certificateValidityPeriodValue") instanceof Number number)
                || number.longValue() < 1) {
            return null;
        }
        long value = number.longValue();
        String scale = string(profile.get("certificateValidityPeriodScale"));
        return switch (scale == null ? "" : scale.toLowerCase(Locale.ROOT)) {
            case "days" -> Duration.ofDays(value);
            case "months" -> Duration.ofHours(730 * value);
            case "years" -> Duration.ofDays(365 * value);
            default -> null;
        };
    }

    private static boolean isScepProfile(Map<String, Object> profile) {
        String type = string(profile.get("@odata.type"));
        return type != null && type.toLowerCase(Locale.ROOT).contains("scepcertificateprofile");
    }

    private static boolean pointsAt(Map<String, Object> profile, String url) {
        return profile.get("scepServerUrls") instanceof List<?> urls
                && urls.stream().anyMatch(candidate -> candidate != null
                        && url.equalsIgnoreCase(normalizeUrl(candidate.toString())));
    }

    private static String normalizeUrl(String url) {
        String trimmed = url.trim();
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    private static String string(Object value) {
        return value == null || value.toString().isBlank() ? null : value.toString().trim();
    }
}
