// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.acme;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.handler.acme.AcmeAccountResult;
import com.certping.agent.handler.acme.AcmeAccountService;
import com.certping.agent.model.enums.CertType;
import com.certping.agent.model.message.CertManualTxtResponse;
import com.certping.agent.model.message.CertManualValidateMessage;
import com.certping.agent.model.message.SanDomainEntry;
import com.certping.agent.ssl.CertificateMetadata;
import com.certping.agent.ssl.CertificateMetadataExtractor;
import com.certping.agent.ssl.CsrKeyPairService;
import com.certping.agent.ssl.IssuanceResult;
import com.certping.agent.ssl.dns.DnsPropagationVerifier;
import com.certping.agent.ssl.dns.DnsValidationDomainService;
import com.certping.agent.secrets.SecretStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNetworkException;
import org.shredzone.acme4j.exception.AcmeRateLimitedException;
import org.springframework.stereotype.Service;

import java.io.StringWriter;
import java.net.URI;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/**
 * Manual Let's Encrypt: {@code requestTxtRecords} creates the ACME order and returns DNS-01 TXT data;
 * {@code completeValidation} verifies TXT in authoritative DNS, completes challenges, finalizes, stores the cert.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LetsEncryptManualService {

    private final AcmeAccountService acmeAccountService;
    private final CsrKeyPairService csrKeyPairService;
    private final SecretStore secretStore;
    private final AgentProperties properties;
    private final DnsPropagationVerifier dnsPropagationVerifier;
    private final DnsValidationDomainService dnsValidationDomainService;

    public ManualTxtResult requestTxtRecords(
            String organizationId,
            String certXref,
            String domain,
            boolean wildcard,
            boolean san,
            List<SanDomainEntry> sanDomainEntries,
            String existingAcmeAccountHandle) {

        log.info("LE manual TXT request: organizationId={}, domain={}, xref={}", organizationId, domain, certXref);

        try {
            AcmeAccountResult account = acmeAccountService.getOrCreate(organizationId, existingAcmeAccountHandle);

            Session session = new Session(properties.getAcme().getDirectoryUrl());
            Login login = session.login(account.accountLocation(), account.keyPair());
            Account acct = login.getAccount();

            List<String> orderDomains = buildOrderDomainList(domain, wildcard, san, sanDomainEntries);
            Order order = createOrderWithRetry(acct, orderDomains);
            log.info("LE manual order created: domain={}, orderDomains={}", domain, orderDomains);

            List<CertManualTxtResponse.TxtRecord> txtRecords = new ArrayList<>();
            for (Authorization auth : order.getAuthorizations()) {
                Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE)
                        .map(ch -> (Dns01Challenge) ch)
                        .orElse(null);
                if (challenge == null) {
                    throw new PermanentAgentException("ACME_NO_DNS_CHALLENGE",
                            "No DNS-01 challenge for auth: " + auth.getIdentifier().getDomain());
                }
                String authDomain = auth.getIdentifier().getDomain();
                String recordName = "_acme-challenge." + authDomain.replaceFirst("^\\*\\.", "");
                String recordValue = challenge.getDigest();
                txtRecords.add(CertManualTxtResponse.TxtRecord.builder()
                        .domain(authDomain)
                        .recordName(recordName)
                        .recordValue(recordValue)
                        .build());
            }

            if (txtRecords.isEmpty()) {
                throw new PermanentAgentException("ACME_NO_AUTHORIZATIONS",
                        "ACME order has no authorizations for domain: " + domain);
            }

            return new ManualTxtResult(
                    txtRecords,
                    order.getLocation(),
                    account.accountLocation(),
                    account.acmeAccountHandle());

        } catch (AcmeNetworkException e) {
            throw new TransientAgentException("ACME_NETWORK_ERROR",
                    "Network error during manual TXT request: " + e.getMessage(), e);
        } catch (AcmeRateLimitedException e) {
            throw toRetryable("manual TXT request", domain, e);
        } catch (AcmeException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "CA_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("LE manual TXT request", domain, e);
            }
            throw new PermanentAgentException("ACME_MANUAL_TXT_FAILED",
                    "ACME manual TXT request failed for " + domain + ": " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TransientAgentException("ACME_INTERRUPTED",
                    "Manual TXT request interrupted: " + e.getMessage(), e);
        } catch (PermanentAgentException | TransientAgentException | RetryableAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "CA_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("LE manual TXT request", domain, e);
            }
            throw new PermanentAgentException("ACME_MANUAL_TXT_FAILED",
                    "Unexpected error during manual TXT request: " + e.getMessage(), e);
        }
    }

    public IssuanceResult completeValidation(
            String organizationId,
            String certXref,
            String domain,
            boolean wildcard,
            boolean san,
            List<SanDomainEntry> sanDomainEntries,
            String acmeOrderUrl,
            String acmeAccountHandle,
            List<CertManualValidateMessage.TxtRecordEntry> txtRecordHints) {

        log.info("LE manual DNS validation: organizationId={}, domain={}, xref={}", organizationId, domain, certXref);

        if (acmeOrderUrl == null || acmeOrderUrl.isBlank()) {
            throw new PermanentAgentException("ACME_ORDER_URL_MISSING", "acmeOrderUrl is required");
        }
        if (acmeAccountHandle == null || acmeAccountHandle.isBlank()) {
            throw new PermanentAgentException("ACME_ACCOUNT_PATH_MISSING", "acmeAccountHandle is required");
        }

        try {
            AcmeAccountResult account = acmeAccountService.getOrCreate(organizationId, acmeAccountHandle);

            URL orderUrl = URI.create(acmeOrderUrl).toURL();
            Session session = new Session(properties.getAcme().getDirectoryUrl());
            Login login = session.login(account.accountLocation(), account.keyPair());
            Order order = login.bindOrder(orderUrl);

            List<DnsPropagationVerifier.TxtRecord> toVerify = new ArrayList<>();
            if (txtRecordHints != null && !txtRecordHints.isEmpty()) {
                for (CertManualValidateMessage.TxtRecordEntry hint : txtRecordHints) {
                    if (hint == null
                            || hint.getRecordName() == null || hint.getRecordName().isBlank()
                            || hint.getRecordValue() == null || hint.getRecordValue().isBlank()) {
                        continue;
                    }
                    toVerify.add(new DnsPropagationVerifier.TxtRecord(
                            hint.getRecordName().trim(), hint.getRecordValue().trim()));
                }
            }
            if (toVerify.isEmpty()) {
                for (Authorization auth : order.getAuthorizations()) {
                    Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE)
                            .map(ch -> (Dns01Challenge) ch)
                            .orElse(null);
                    if (challenge != null) {
                        String authDomain = auth.getIdentifier().getDomain();
                        String recordName = "_acme-challenge." + authDomain.replaceFirst("^\\*\\.", "");
                        toVerify.add(new DnsPropagationVerifier.TxtRecord(recordName, challenge.getDigest()));
                    }
                }
            }
            if (toVerify.isEmpty()) {
                throw new PermanentAgentException("ACME_NO_DNS_CHALLENGE",
                        "No DNS-01 TXT records to verify for manual validation - order may have no authorizations");
            }

            dnsPropagationVerifier.verifyAll(toVerify);

            AgentProperties.ChallengeProperties cfg = properties.getAcme().getChallenge();
            for (Authorization auth : order.getAuthorizations()) {
                Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE)
                        .map(ch -> (Dns01Challenge) ch)
                        .orElse(null);
                if (challenge != null && challenge.getStatus() != Status.VALID) {
                    challenge.trigger();
                    log.info("Challenge triggered for {}", auth.getIdentifier().getDomain());
                }
            }

            for (Authorization auth : order.getAuthorizations()) {
                Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE)
                        .map(ch -> (Dns01Challenge) ch)
                        .orElse(null);
                if (challenge == null) {
                    continue;
                }
                String authDomain = auth.getIdentifier().getDomain();
                Status challengeStatus = challenge.getStatus();
                if (challengeStatus != Status.VALID && challengeStatus != Status.INVALID) {
                    try {
                        challengeStatus = AcmePollingSupport.waitForChallengeCompletion(challenge, cfg);
                    } catch (AcmeException e) {
                        throw new PermanentAgentException("ACME_CHALLENGE_TIMEOUT",
                                "DNS-01 challenge did not become VALID for " + authDomain
                                        + " after " + cfg.getMaxAttempts() + " attempts", e);
                    }
                }
                log.debug("Challenge status={} for {}", challengeStatus, authDomain);
                if (challengeStatus == Status.INVALID) {
                    String problem = AcmePollingSupport.problemOf(challenge);
                    log.warn("DNS-01 challenge for {} was rejected (INVALID){}", authDomain, problem);
                    throw new PermanentAgentException("ACME_CHALLENGE_FAILED",
                            "DNS-01 challenge INVALID for " + authDomain + problem
                                    + ": TXT may be wrong or not propagated.");
                }
                if (challengeStatus != Status.VALID) {
                    throw new PermanentAgentException("ACME_CHALLENGE_TIMEOUT",
                            "DNS-01 challenge did not become VALID for " + authDomain
                                    + " after " + cfg.getMaxAttempts() + " attempts - status: " + challengeStatus);
                }
                Status authorizationStatus;
                try {
                    authorizationStatus = AcmePollingSupport.requireValidAuthorization(
                        auth,
                        authDomain,
                        cfg,
                        log);
                } catch (AcmeException e) {
                    throw new PermanentAgentException("ACME_CHALLENGE_TIMEOUT",
                        "Authorization did not become VALID for " + authDomain
                            + " after " + cfg.getMaxAttempts() + " attempts", e);
                }
                if (authorizationStatus == Status.INVALID) {
                    throw new PermanentAgentException("ACME_CHALLENGE_FAILED",
                        "Authorization INVALID for " + authDomain + " - TXT may be wrong or not propagated.");
                }
                if (authorizationStatus != Status.VALID) {
                    throw new PermanentAgentException("ACME_CHALLENGE_TIMEOUT",
                        "Authorization did not become VALID for " + authDomain
                            + " after " + cfg.getMaxAttempts() + " attempts - status: " + authorizationStatus);
                }
            }

            List<String> orderDomains = buildOrderDomainList(domain, wildcard, san, sanDomainEntries);
            String primaryCsr = orderDomains.get(0);
            List<String> sanForCsr = new ArrayList<>();
            for (int i = 1; i < orderDomains.size(); i++) {
                sanForCsr.add(orderDomains.get(i));
            }

            log.info("LE manual finalize identifiers: primary={}, sans={}", primaryCsr, sanForCsr);

            CsrKeyPairService.CsrKeyPairResult csr = csrKeyPairService.generateCsrAndKeyPair(primaryCsr, sanForCsr);
            executeOrderWithRetry(order, csr.csrDer());
            waitForOrderValid(order, domain);

            Certificate certificate = order.getCertificate();
            List<X509Certificate> chain = certificate.getCertificateChain();
            X509Certificate leaf = chain.get(0);

            String chainPem = buildChainPem(chain);
            String bundle = chainPem + "\n" + csr.privateKeyPem();

            String certSecretHandle = secretStore.create(certXref, bundle);
            log.info("LE manual cert stored at {}", certSecretHandle);

            String serial = leaf.getSerialNumber().toString(16).toUpperCase();
            String fingerprint = sha256Fingerprint(leaf);
            OffsetDateTime validFrom = leaf.getNotBefore().toInstant().atOffset(ZoneOffset.UTC);
            OffsetDateTime validTo = leaf.getNotAfter().toInstant().atOffset(ZoneOffset.UTC);
            String issuer = leaf.getIssuerX500Principal().getName();
            CertificateMetadata metadata = CertificateMetadataExtractor.fromLeaf(leaf);

            return new IssuanceResult(certSecretHandle, null, acmeAccountHandle, serial, fingerprint, validFrom, validTo, issuer, null,
                    metadata.signatureAlgorithm(),
                    metadata.signatureAlgorithmOid(),
                    metadata.subjectDn(),
                    metadata.commonName(),
                    metadata.publicKeyAlgorithm(),
                    metadata.keySize(),
                    metadata.publicKeyCurve(),
                    metadata.keyUsage(),
                    metadata.extendedKeyUsage(),
                    metadata.subjectKeyIdentifier(),
                    metadata.authorityKeyIdentifier(),
                    CertType.DV);

        } catch (AcmeNetworkException e) {
            throw new TransientAgentException("ACME_NETWORK_ERROR",
                    "Network error during manual validation: " + e.getMessage(), e);
        } catch (AcmeRateLimitedException e) {
            throw toRetryable("manual validation", domain, e);
        } catch (AcmeException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "CA_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("LE manual validation", domain, e);
            }
            throw new PermanentAgentException("ACME_MANUAL_VALIDATE_FAILED",
                    "ACME manual validation failed for " + domain + ": " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TransientAgentException("ACME_INTERRUPTED",
                    "Manual validation interrupted: " + e.getMessage(), e);
        } catch (PermanentAgentException | TransientAgentException | RetryableAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "CA_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("LE manual validation", domain, e);
            }
            throw new PermanentAgentException("ACME_MANUAL_VALIDATE_FAILED",
                    "Unexpected error during manual validation: " + e.getMessage(), e);
        }
    }

    private List<String> flattenPatterns(boolean san, List<SanDomainEntry> entries) {
        if (!san || entries == null || entries.isEmpty()) {
            return List.of();
        }
        return entries.stream()
                .filter(e -> e.getPatterns() != null)
                .flatMap(e -> e.getPatterns().stream())
                .distinct()
                .toList();
    }

    private List<String> buildOrderDomainList(
            String domain,
            boolean wildcard,
            boolean san,
            List<SanDomainEntry> sanDomainEntries) {
        List<String> sanList = flattenPatterns(san, sanDomainEntries);
        return dnsValidationDomainService.buildCertificateDomains(domain, wildcard, sanList);
    }

    private Order createOrderWithRetry(Account account, List<String> domains)
            throws AcmeException, InterruptedException {
        try {
            return account.newOrder().domains(domains).create();
        } catch (AcmeRateLimitedException e) {
            throw toRetryable("manual order creation", firstDomain(domains), e);
        }
    }

    private void executeOrderWithRetry(Order order, byte[] csrDer) throws AcmeException {
        try {
            order.execute(csrDer);
        } catch (AcmeRateLimitedException e) {
            throw toRetryable("manual order execute", "unknown-domain", e);
        }
    }

    /**
     * Builds the {@link RetryableAgentException} the listener uses to re-schedule the message on
     * the agent's queue, so no thread sleeps through the wait. Honors LE's {@code Retry-After}
     * when present; otherwise leaves it null so the listener applies its blind backoff curve.
     */
    private RetryableAgentException toRetryable(String operation, String domain, AcmeRateLimitedException e) {
        Duration retryAfter = retryAfterDuration(e);
        log.warn("LE rate limited on {} for {} — re-scheduling on the agent's queue (retryAfter={})",
                operation, domain, retryAfter);
        return new RetryableAgentException("ACME_RATE_LIMITED",
                "LE rate limited on " + operation + " for " + domain + ": " + e.getMessage(),
                retryAfter, e);
    }

    private Duration retryAfterDuration(AcmeRateLimitedException e) {
        return e.getRetryAfter()
                .filter(t -> t.isAfter(Instant.now()))
                .map(t -> Duration.between(Instant.now(), t))
                .orElse(null);
    }

    private String firstDomain(List<String> domains) {
        return (domains == null || domains.isEmpty()) ? "unknown-domain" : domains.get(0);
    }

    private void waitForOrderValid(Order order, String domain) throws AcmeException, InterruptedException {
        AgentProperties.ChallengeProperties cfg = properties.getAcme().getChallenge();
        Status orderStatus;
        try {
            orderStatus = AcmePollingSupport.waitForOrderCompletion(order, cfg);
        } catch (AcmeException e) {
            throw new PermanentAgentException("ACME_ORDER_TIMEOUT",
                    "ACME order did not reach VALID for " + domain + " - status: " + order.getStatus(), e);
        }
        log.debug("Order status={} for domain {}", orderStatus, domain);
        if (orderStatus != Status.VALID) {
            throw new PermanentAgentException("ACME_ORDER_TIMEOUT",
                    "ACME order did not reach VALID for " + domain + " - status: " + orderStatus);
        }
    }

    private String buildChainPem(List<X509Certificate> chain) throws Exception {
        StringWriter sw = new StringWriter();
        for (X509Certificate cert : chain) {
            sw.write("-----BEGIN CERTIFICATE-----\n");
            sw.write(java.util.Base64.getMimeEncoder(64, new byte[]{'\n'})
                    .encodeToString(cert.getEncoded()));
            sw.write("\n-----END CERTIFICATE-----\n");
        }
        return sw.toString();
    }

    private String sha256Fingerprint(X509Certificate cert) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(cert.getEncoded());
            return HexFormat.of().withUpperCase().withDelimiter(":").formatHex(digest);
        } catch (Exception e) {
            log.warn("Failed to compute fingerprint: {}", e.getMessage());
            return "unknown";
        }
    }
}


