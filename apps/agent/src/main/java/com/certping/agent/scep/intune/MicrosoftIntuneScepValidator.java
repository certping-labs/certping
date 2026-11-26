// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep.intune;

import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.platform.DeviceSourceCredentialRegistry;
import com.certping.agent.scep.ChallengeValidationException;
import com.certping.agent.scep.IntuneUnavailableException;
import com.certping.agent.scep.ResolvedEndpoint;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Real Intune challenge validator. The tenant credential is resolved per request from the
 * endpoint's {@code connectionProfileRef} through {@link DeviceSourceCredentialRegistry} — the same
 * store that owns the credential for device sync — so each SCEP source route validates against its
 * own Intune tenant and no secret is ever copied into the endpoint record.
 *
 * <p>Delegates the transport to {@link IntuneScepClient}: a rejected challenge surfaces as a
 * {@link ChallengeValidationException} (signed {@code CertRep FAILURE}); an unreachable service as an
 * {@link IntuneUnavailableException} (HTTP 503, device retries).
 */
@Slf4j
public class MicrosoftIntuneScepValidator implements IntuneScepValidator {

    /**
     * Entra client-credentials tokens live 60–90 minutes; caching briefly keeps a fleet
     * enrollment burst from hammering the token endpoint (a 429 amplifier) while staying far
     * inside the token lifetime. A token revoked mid-window fails as transient and retries.
     */
    private static final Duration TOKEN_CACHE_TTL = Duration.ofMinutes(5);

    private final IntuneScepClient client;
    private final DeviceSourceCredentialRegistry credentialRegistry;
    private final ObjectMapper objectMapper;
    private final String callerInfo;
    /** Discovered ScepRequestValidationFEService base URL per source route; it rarely changes. */
    private final Map<String, String> serviceUrlByProfileRef = new ConcurrentHashMap<>();
    /** Short-lived token cache keyed by (tenantId, clientId, scope). */
    private final Map<String, CachedToken> tokenCache = new ConcurrentHashMap<>();

    public MicrosoftIntuneScepValidator(IntuneScepClient client,
                                        DeviceSourceCredentialRegistry credentialRegistry,
                                        ObjectMapper objectMapper, String callerInfo) {
        this.client = client;
        this.credentialRegistry = credentialRegistry;
        this.objectMapper = objectMapper;
        this.callerInfo = callerInfo;
    }

    @Override
    public boolean validatesWithMicrosoft() {
        return true;
    }

    @Override
    public ScepValidationResult validate(ResolvedEndpoint endpoint, String transactionId, String csrBase64) {
        log.debug("Validating SCEP challenge against Intune: profile={} txn={}",
                endpoint.connectionProfileRef(), transactionId);
        TenantCredentials credentials = credentials(endpoint);
        client.validateRequest(serviceUrl(endpoint, credentials), manageToken(credentials),
                transactionId, csrBase64, callerInfo);
        // ValidateRequest proves the challenge, not any individual field of the request. Identifier
        // extraction (and its ASSERTED provenance) is the caller's separate, XXE-safe step.
        return ScepValidationResult.absent();
    }

    @Override
    public void notifySuccess(ResolvedEndpoint endpoint, String transactionId, String csrBase64,
                              String thumbprint, String serial, String expiryIso, String issuer,
                              String caConfig, String certAuthority) {
        TenantCredentials credentials = credentials(endpoint);
        client.sendSuccessNotification(serviceUrl(endpoint, credentials), manageToken(credentials),
                transactionId, csrBase64, thumbprint, serial, expiryIso, issuer, caConfig,
                certAuthority, callerInfo);
    }

    @Override
    public void notifyFailure(ResolvedEndpoint endpoint, String transactionId, String csrBase64,
                              long hResult, String description) {
        TenantCredentials credentials = credentials(endpoint);
        client.sendFailureNotification(serviceUrl(endpoint, credentials), manageToken(credentials),
                transactionId, csrBase64, hResult, description, callerInfo);
    }

    private TenantCredentials credentials(ResolvedEndpoint endpoint) {
        try {
            String credentialsJson = credentialRegistry.requireCredentialsJson(
                    endpoint.connectionProfileRef(), DevicePlatformType.INTUNE);
            JsonNode json = objectMapper.readTree(credentialsJson);
            return new TenantCredentials(
                    requiredField(json, "tenantId"),
                    requiredField(json, "clientId"),
                    requiredField(json, "clientSecret"));
        } catch (IntuneUnavailableException exception) {
            throw exception;
        } catch (Exception exception) {
            // Covers a registry miss too, so the device gets a retryable 503 instead of a 500.
            // Never include credential content in the message.
            throw new IntuneUnavailableException("Intune credentials for source "
                    + endpoint.connectionProfileRef() + " could not be resolved");
        }
    }

    private static String requiredField(JsonNode json, String field) {
        JsonNode value = json.get(field);
        if (value == null || !value.isString() || value.stringValue().isBlank()) {
            throw new IntuneUnavailableException("Intune credentials are missing " + field);
        }
        return value.stringValue();
    }

    private String manageToken(TenantCredentials credentials) {
        return cachedToken(credentials, IntuneScepClient.MANAGE_SCOPE);
    }

    private String serviceUrl(ResolvedEndpoint endpoint, TenantCredentials credentials) {
        String cached = serviceUrlByProfileRef.get(endpoint.connectionProfileRef());
        if (cached != null) {
            return cached;
        }
        String graphToken = cachedToken(credentials, IntuneScepClient.GRAPH_SCOPE);
        String discovered = client.discoverValidationServiceUrl(graphToken);
        serviceUrlByProfileRef.put(endpoint.connectionProfileRef(), discovered);
        return discovered;
    }

    private String cachedToken(TenantCredentials credentials, String scope) {
        // App registrations in one tenant are distinct security principals. Never let a source
        // route borrow another source's token merely because both belong to the same tenant.
        String key = credentials.tenantId() + "|" + credentials.clientId() + "|" + scope;
        Instant now = Instant.now();
        CachedToken cached = tokenCache.get(key);
        if (cached != null && cached.expiresAt().isAfter(now)) {
            return cached.token();
        }
        String token = client.acquireToken(credentials.tenantId(), credentials.clientId(),
                credentials.clientSecret(), scope);
        tokenCache.put(key, new CachedToken(token, now.plus(TOKEN_CACHE_TTL)));
        return token;
    }

    private record CachedToken(String token, Instant expiresAt) {
    }

    private record TenantCredentials(String tenantId, String clientId, String clientSecret) {
    }
}
