// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.ProviderThrottleCodes;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.route53.Route53Client;
import software.amazon.awssdk.services.route53.model.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * AWS Route 53 DNS provider, on AWS SDK v2.
 * Credentials passed via constructor (from the credential JSON in the secret store), not env vars.
 *
 * Expected credential JSON in KV: {"accessKeyId":"...","secretAccessKey":"..."}
 */
@Slf4j
public class AwsRoute53DnsProvider implements DnsProvider {

    private final Route53Client route53;

    public AwsRoute53DnsProvider(String accessKeyId, String secretAccessKey) {
        if (accessKeyId == null || accessKeyId.isBlank()
                || secretAccessKey == null || secretAccessKey.isBlank()) {
            throw new PermanentAgentException("DNS_CREDENTIAL_INVALID",
                    "AWS Route53 accessKeyId / secretAccessKey is blank");
        }
        this.route53 = Route53Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(accessKeyId, secretAccessKey)))
                .region(Region.AWS_GLOBAL) // Route53 is a global service
                .build();
    }

    /**
     * A TXT value joins the values already at the name, so the apex and its wildcard can be validated at once;
     * the returned id is the value, which the delete removes alone. A CNAME replaces the set.
     */
    @Override
    public String addRecord(DnsRecordType type, String recordName, String value) {
        try {
            String domain = stripChallengePrefix(recordName);
            String hostedZoneId = findHostedZoneId(domain);
            ResourceRecord ours = ResourceRecord.builder()
                    .value(type == DnsRecordType.TXT ? quoted(value) : value + ".")
                    .build();

            List<ResourceRecord> values = new ArrayList<>(List.of(ours));
            long ttl = 60L;
            if (type == DnsRecordType.TXT) {
                Optional<ResourceRecordSet> existing = existingSet(hostedZoneId, recordName, type);
                if (existing.isPresent()) {
                    values = new ArrayList<>(existing.get().resourceRecords());
                    ttl = existing.get().ttl() == null ? ttl : existing.get().ttl();
                    if (!values.contains(ours)) {
                        values.add(ours);
                    }
                }
            }

            String changeId = change(hostedZoneId, ChangeAction.UPSERT, ResourceRecordSet.builder()
                    .name(recordName)
                    .type(rrType(type))
                    .ttl(ttl)
                    .resourceRecords(values)
                    .build());
            log.info("Route53 {} record added for {}, changeId={}", type, recordName, changeId);
            return type == DnsRecordType.TXT ? value : changeId;

        } catch (Route53Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl = classifyRoute53Throttle(e);
            if (rl.isPresent()) {
                throw rl.get().toRetryable("route53 ChangeResourceRecordSets", recordName, e);
            }
            if (e.statusCode() == 401 || e.statusCode() == 403
                    || "AccessDenied".equals(e.awsErrorDetails().errorCode())) {
                throw new PermanentAgentException("DNS_AUTH_FAILED",
                        "Route53 access denied: " + e.getMessage(), e);
            }
            throw new TransientAgentException("DNS_PROVIDER_ERROR",
                    "Route53 " + type + " create failed: " + e.getMessage(), e);
        }
    }

    /** Removes only the TXT value {@code recordId} names, keeping any others at the name. */
    @Override
    public void deleteRecord(DnsRecordType type, String recordName, String recordId) {
        try {
            String domain = stripChallengePrefix(recordName);
            String hostedZoneId = findHostedZoneId(domain);

            Optional<ResourceRecordSet> existing = existingSet(hostedZoneId, recordName, type);
            if (existing.isEmpty()) {
                log.info("Route53 {} record {} already gone, skipping deletion", type, recordName);
                return;
            }
            ResourceRecordSet set = existing.get();
            if (type == DnsRecordType.TXT) {
                List<ResourceRecord> remaining = set.resourceRecords().stream()
                        .filter(r -> !quoted(recordId).equals(r.value()))
                        .toList();
                if (remaining.size() == set.resourceRecords().size()) {
                    log.info("Route53 TXT value at {} already gone, skipping deletion", recordName);
                    return;
                }
                if (!remaining.isEmpty()) {
                    change(hostedZoneId, ChangeAction.UPSERT, set.toBuilder().resourceRecords(remaining).build());
                    log.info("Route53 TXT value deleted at {}; {} other value(s) kept", recordName, remaining.size());
                    return;
                }
            }
            change(hostedZoneId, ChangeAction.DELETE, set);
            log.info("Route53 {} record deleted: {}", type, recordName);

        } catch (Route53Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl = classifyRoute53Throttle(e);
            if (rl.isPresent()) {
                throw rl.get().toRetryable("route53 ChangeResourceRecordSets (delete)", recordName, e);
            }
            log.warn("Route53 {} delete failed for {}: {}; treating as non-fatal",
                    type, recordName, e.getMessage());
        }
    }

    private Optional<ResourceRecordSet> existingSet(String hostedZoneId, String recordName, DnsRecordType type) {
        List<ResourceRecordSet> sets = route53.listResourceRecordSets(
                ListResourceRecordSetsRequest.builder()
                        .hostedZoneId(hostedZoneId)
                        .startRecordName(recordName)
                        .startRecordType(rrType(type))
                        .maxItems("1")
                        .build()).resourceRecordSets();
        String wanted = withoutTrailingDot(recordName);
        return sets.stream()
                .filter(set -> set.type() == rrType(type) && withoutTrailingDot(set.name()).equalsIgnoreCase(wanted))
                .findFirst();
    }

    private String change(String hostedZoneId, ChangeAction action, ResourceRecordSet set) {
        return route53.changeResourceRecordSets(
                ChangeResourceRecordSetsRequest.builder()
                        .hostedZoneId(hostedZoneId)
                        .changeBatch(ChangeBatch.builder()
                                .changes(Change.builder().action(action).resourceRecordSet(set).build())
                                .build())
                        .build()).changeInfo().id();
    }

    private static String quoted(String value) {
        return "\"" + value + "\"";
    }

    private static String withoutTrailingDot(String name) {
        return name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
    }

    /**
     * Route53 surfaces throttle as HTTP 400 with errorCode {@code Throttling} (the 5 req/sec/account
     * quota) or {@code PriorRequestNotComplete} (per-hosted-zone serialization on
     * ChangeResourceRecordSets). Neither is recognised by {@link AwsServiceException#isThrottlingException()}
     * in current SDK v2 because the wire code lacks the "Exception" suffix the SDK's matcher expects
     * (aws/aws-sdk-java-v2 #2969). We layer:
     *   1) {@link RateLimitClassifier#fromAws} for the standard 429/503/known-code path,
     *   2) explicit Route53 error-code match for the two strings above,
     *   3) heuristic {@link RateLimitClassifier#classify} on message body ("rate exceeded", etc.)
     *      as a last-ditch belt-and-suspenders.
     * Retry-After is not returned for either Route53 throttle shape — listener applies blind backoff.
     */
    private Optional<RateLimitClassifier.RateLimitVerdict> classifyRoute53Throttle(Route53Exception e) {
        Optional<RateLimitClassifier.RateLimitVerdict> typed =
                RateLimitClassifier.fromAws(e, "DNS_PROVIDER_THROTTLED");
        if (typed.isPresent()) {
            return typed;
        }
        // Force-route the AWS-documented throttle codes (incl. Route53's bare "Throttling" and
        // "PriorRequestNotComplete" returned at HTTP 400) through the heuristic by wrapping
        // in a ThrottlingException-named cause that classify() recognises by class-name shape.
        // The code list lives in ProviderThrottleCodes.AWS_THROTTLE_ERROR_CODES so additions
        // are doc-cited in one place rather than scattered through adapters.
        String code = e.awsErrorDetails() != null ? e.awsErrorDetails().errorCode() : null;
        if (code != null && ProviderThrottleCodes.AWS_THROTTLE_ERROR_CODES.contains(code)) {
            return RateLimitClassifier.classify(new Route53ThrottlingException(e), "DNS_PROVIDER_THROTTLED");
        }
        return RateLimitClassifier.classify(e, "DNS_PROVIDER_THROTTLED");
    }

    /** Class-name shape ({@code *Throttling*}) lets {@link RateLimitClassifier#classify} recognise
     *  Route53's HTTP-400 throttle responses ({@code Throttling} / {@code PriorRequestNotComplete})
     *  that {@code AwsServiceException.isThrottlingException()} misses. */
    private static final class Route53ThrottlingException extends RuntimeException {
        Route53ThrottlingException(Route53Exception cause) {
            super(cause.getMessage(), cause);
        }
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    private String findHostedZoneId(String domain) {
        String rootDomain = getRegistrableDomain(domain);
        ListHostedZonesByNameResponse resp = route53.listHostedZonesByName(
                ListHostedZonesByNameRequest.builder()
                        .dnsName(rootDomain)
                        .maxItems("1")
                        .build());

        if (resp.hostedZones().isEmpty()) {
            throw new PermanentAgentException("DNS_ZONE_NOT_FOUND",
                    "No Route53 hosted zone found for domain: " + domain);
        }
        String id = resp.hostedZones().get(0).id();
        return id.startsWith("/hostedzone/") ? id.substring("/hostedzone/".length()) : id;
    }

    private String stripChallengePrefix(String recordName) {
        String domain = recordName;
        if (domain.startsWith("_acme-challenge.")) {
            domain = domain.substring("_acme-challenge.".length());
        }
        if (domain.startsWith("*.")) {
            domain = domain.substring(2);
        }
        return domain;
    }

    private String getRegistrableDomain(String domain) {
        String[] parts = domain.split("\\.");
        if (parts.length >= 2) {
            return parts[parts.length - 2] + "." + parts[parts.length - 1];
        }
        return domain;
    }

    private static RRType rrType(DnsRecordType type) {
        return type == DnsRecordType.TXT ? RRType.TXT : RRType.CNAME;
    }
}
