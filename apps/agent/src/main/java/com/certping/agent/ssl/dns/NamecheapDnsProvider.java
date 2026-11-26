// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import lombok.extern.slf4j.Slf4j;
import org.w3c.dom.Document;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Namecheap DNS provider for certificate-validation TXT records.
 *
 * <p>Namecheap {@code setHosts} replaces the full host record set, so this provider
 * always fetches existing records, edits only the ACME TXT entry, then writes the
 * complete record list back.
 *
 * <p>The credential JSON supplies {@code apiUser}, {@code apiKey}, and
 * {@code username}. The Namecheap-whitelisted public client IP is supplied through
 * the {@code NAMECHEAP_CLIENT_IP} environment variable by {@link DnsProviderFactory}.
 * API credentials and TXT challenge values are not written to logs.
 */
@Slf4j
public class NamecheapDnsProvider implements DnsProvider {

    private static final String API_BASE = "https://api.namecheap.com/xml.response";
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private static final int RECORD_TTL_SECONDS = 60;

    private final String apiUser;
    private final String apiKey;
    private final String username;
    private final String clientIp;
    private final HttpClient httpClient;

    public NamecheapDnsProvider(String apiUser, String apiKey, String username, String clientIp) {
        if (isBlank(apiUser) || isBlank(apiKey) || isBlank(username) || isBlank(clientIp)) {
            throw new PermanentAgentException("DNS_CREDENTIAL_INVALID",
                    "Namecheap apiUser / apiKey / username / clientIp is blank");
        }
        this.apiUser = apiUser;
        this.apiKey = apiKey;
        this.username = username;
        this.clientIp = clientIp;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(REQUEST_TIMEOUT)
                .build();
    }

    @Override
    public String addRecord(DnsRecordType type, String recordName, String value) {
        try {
            NamecheapZoneHost zoneHost = NamecheapZoneHost.fromRecordName(recordName);
            String address = addressFor(type, value);
            List<NamecheapDnsRecord> records = getHosts(zoneHost);
            if (records.stream().noneMatch(record -> record.matches(type, zoneHost.hostName(), address))) {
                records = new ArrayList<>(records);
                records.add(new NamecheapDnsRecord(zoneHost.hostName(), type.name(), address,
                        null, String.valueOf(RECORD_TTL_SECONDS), null, null));
                setHosts(zoneHost, records);
            }
            String recordId = NamecheapRecordId.encode(zoneHost, address);
            log.info("Namecheap {} record added: {}", type, recordName);
            return recordId;
        } catch (PermanentAgentException | TransientAgentException | RetryableAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DNS_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("namecheap " + type + " create", recordName, e);
            }
            throw new TransientAgentException("DNS_PROVIDER_ERROR",
                    "Namecheap " + type + " create error: " + e.getMessage(), e);
        }
    }

    @Override
    public void deleteRecord(DnsRecordType type, String recordName, String recordId) {
        try {
            NamecheapRecordId parsedId = NamecheapRecordId.parse(recordId);
            NamecheapZoneHost zoneHost = NamecheapZoneHost.fromRecordName(recordName);
            if (!parsedId.domain().equalsIgnoreCase(zoneHost.domain())
                    || !parsedId.hostName().equalsIgnoreCase(zoneHost.hostName())) {
                log.warn("Namecheap recordId does not match recordName '{}', skipping deletion", recordName);
                return;
            }

            List<NamecheapDnsRecord> records = getHosts(zoneHost);
            List<NamecheapDnsRecord> remainingRecords = records.stream()
                    .filter(record -> !record.matches(type, parsedId.hostName(), parsedId.value()))
                    .toList();
            if (remainingRecords.size() != records.size()) {
                setHosts(zoneHost, remainingRecords);
            }
            log.info("Namecheap {} record deleted: {}", type, recordName);
        } catch (RetryableAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DNS_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("namecheap " + type + " delete", recordName, e);
            }
            log.warn("Namecheap {} delete failed for {}: {} - treating as non-fatal",
                    type, recordName, e.getMessage());
        }
    }

    /** Namecheap takes a CNAME target as a fully qualified name, with its trailing dot. */
    private static String addressFor(DnsRecordType type, String value) {
        return type == DnsRecordType.CNAME ? value + "." : value;
    }

    private List<NamecheapDnsRecord> getHosts(NamecheapZoneHost zoneHost) throws Exception {
        Document doc = execute("namecheap.domains.dns.getHosts", zoneHost, List.of());
        NamecheapDnsXml.verifyGetHostsSuccess(doc, "Namecheap getHosts failed");
        return NamecheapDnsXml.hostRecords(doc);
    }

    private void setHosts(NamecheapZoneHost zoneHost, List<NamecheapDnsRecord> records) throws Exception {
        List<NamecheapQueryParam> params = new ArrayList<>();
        for (int i = 0; i < records.size(); i++) {
            int index = i + 1;
            NamecheapDnsRecord record = records.get(i);
            params.add(new NamecheapQueryParam("HostName" + index, record.name()));
            params.add(new NamecheapQueryParam("RecordType" + index, record.type()));
            params.add(new NamecheapQueryParam("Address" + index, record.address()));
            NamecheapQueryParam.addOptional(params, "MXPref" + index, record.mxPref());
            NamecheapQueryParam.addOptional(params, "TTL" + index, record.ttl());
            NamecheapQueryParam.addOptional(params, "Flag" + index, record.flag());
            NamecheapQueryParam.addOptional(params, "Tag" + index, record.tag());
        }
        Document doc = execute("namecheap.domains.dns.setHosts", zoneHost, params);
        NamecheapDnsXml.verifySetHostsSuccess(doc, "Namecheap setHosts failed");
    }

    private Document execute(String command, NamecheapZoneHost zoneHost, List<NamecheapQueryParam> extraParams) throws Exception {
        List<NamecheapQueryParam> params = new ArrayList<>(List.of(
                new NamecheapQueryParam("ApiUser", apiUser),
                new NamecheapQueryParam("ApiKey", apiKey),
                new NamecheapQueryParam("UserName", username),
                new NamecheapQueryParam("ClientIp", clientIp),
                new NamecheapQueryParam("Command", command),
                new NamecheapQueryParam("SLD", zoneHost.sld()),
                new NamecheapQueryParam("TLD", zoneHost.tld())));
        params.addAll(extraParams);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(API_BASE + "?" + NamecheapQueryParam.buildQuery(params)))
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 401 || response.statusCode() == 403) {
            throw new PermanentAgentException("DNS_AUTH_FAILED",
                    "Namecheap auth failed: HTTP " + response.statusCode());
        }
        if (isThrottled(response.statusCode())) {
            throw retryable("namecheap " + command, zoneHost.domain(), response);
        }
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new TransientAgentException("DNS_PROVIDER_ERROR",
                    "Namecheap API HTTP " + response.statusCode());
        }
        return NamecheapDnsXml.parse(response.body());
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static boolean isThrottled(int statusCode) {
        return statusCode == 429 || statusCode == 503;
    }

    private static RetryableAgentException retryable(String operation, String target, HttpResponse<?> response) {
        Duration retryAfter = response.headers() == null
                ? null
                : response.headers()
                        .firstValue("Retry-After")
                        .flatMap(RateLimitClassifier::parseRetryAfterValueOpt)
                        .orElse(null);
        return new RetryableAgentException("DNS_PROVIDER_THROTTLED",
                operation + " for " + target + " was rate-limited (HTTP "
                        + response.statusCode() + (retryAfter == null
                                ? ", no Retry-After supplied)"
                                : ", Retry-After=" + retryAfter + ")"),
                retryAfter, null);
    }
}
