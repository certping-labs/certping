// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.acme;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.CheckpointRecorder;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.handler.acme.AcmeAccountResult;
import com.certping.agent.handler.acme.AcmeAccountService;
import com.certping.agent.model.enums.CertType;
import com.certping.agent.ssl.CertificateMetadata;
import com.certping.agent.ssl.CertificateMetadataExtractor;
import com.certping.agent.ssl.CsrKeyPairService;
import com.certping.agent.ssl.IssuanceResult;
import com.certping.agent.ssl.KeyCustody;
import com.certping.agent.ssl.dns.DnsProvider;
import com.certping.agent.ssl.dns.DnsTxtCleanupService;
import com.certping.agent.ssl.dns.DnsTxtWorkflowService;
import com.certping.agent.ssl.dns.DnsValidationDomainService;
import com.certping.agent.secrets.SecretStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.exception.AcmeNetworkException;
import org.shredzone.acme4j.exception.AcmeRateLimitedException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.exception.AcmeException;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class LetsEncryptAcmeService {

    private final AcmeAccountService acmeAccountService;
    private final CsrKeyPairService csrKeyPairService;
    private final SecretStore secretStore;
    private final AgentProperties properties;
    private final DnsTxtCleanupService dnsTxtCleanupService;
    private final DnsValidationDomainService dnsValidationDomainService;
    private final DnsTxtWorkflowService dnsTxtWorkflowService;
    private final com.certping.agent.ssl.KeyStagingHelper keyStagingHelper;

    /**
     * Issue (or renew) a certificate via Let's Encrypt ACME.
     *
     * @param organizationId  organization identifier
     * @param certificateXref cert reference
     * @param domain          primary domain (CN)
     * @param sanDomains      SAN domain list (flattened from sanDomainEntries)
     * @param rootDnsProvider DNS provider for the primary domain
     * @param sanDnsProviders map of domain pattern → DnsProvider for per-SAN
     *                        routing
     *                        (keyed by exact domain or wildcard pattern, e.g.
     *                        "*.example.com")
     * @param acmeAccountHandle KV URI of existing ACME account key, or null on first
     *                        issuance
     */
    public IssuanceResult issue(
            String organizationId,
            String certificateXref,
            String domain,
            boolean wildcardPrimary,
            List<String> sanDomains,
            DnsProvider rootDnsProvider,
            Map<String, DnsProvider> sanDnsProviders,
            String acmeAccountHandle,
            Integer validityDays) {
        return issue(organizationId, certificateXref, domain, wildcardPrimary, sanDomains,
                rootDnsProvider, sanDnsProviders, acmeAccountHandle, validityDays, null, null, false,
                CheckpointRecorder.NONE);
    }

    /** Overload that accepts a resume checkpoint from a prior failed attempt. */
    public IssuanceResult issue(
            String organizationId,
            String certificateXref,
            String domain,
            boolean wildcardPrimary,
            List<String> sanDomains,
            DnsProvider rootDnsProvider,
            Map<String, DnsProvider> sanDnsProviders,
            String acmeAccountHandle,
            Integer validityDays,
            com.certping.agent.exception.IssuanceCheckpoint resumeCheckpoint) {
        return issue(organizationId, certificateXref, domain, wildcardPrimary, sanDomains,
                rootDnsProvider, sanDnsProviders, acmeAccountHandle, validityDays, resumeCheckpoint, null, false,
                CheckpointRecorder.NONE);
    }

    /**
     * Overload that accepts an ACME ARI hint — the KV URI of the previous cert being renewed.
     * When non-null, the new order is created with {@code newOrder.replaces(previousCert)} so LE
     * grants the duplicate-cert-limit exemption and marks the old cert as superseded.
     *
     * @param previousCertSecretHandle KV URI of the prior cert PEM, or null for first issuance / non-renewal.
     * @param finalPropagationWait     this attempt's DNS propagation wait is the last one allowed
     */
    public IssuanceResult issue(
            String organizationId,
            String certificateXref,
            String domain,
            boolean wildcardPrimary,
            List<String> sanDomains,
            DnsProvider rootDnsProvider,
            Map<String, DnsProvider> sanDnsProviders,
            String acmeAccountHandle,
            Integer validityDays,
            com.certping.agent.exception.IssuanceCheckpoint resumeCheckpoint,
            String previousCertSecretHandle,
            boolean finalPropagationWait,
            CheckpointRecorder recorder) {

        if (validityDays != null) {
            log.warn("LE ignores requested validityDays={}; the ACME CA chooses the lifetime", validityDays);
        }
        log.info("LE issuance started: organizationId={}, domain={}, xref={}, resumeStep={}",
                organizationId, domain, certificateXref,
                resumeCheckpoint == null ? "none" : resumeCheckpoint.step());

        AcmeAccountResult acmeAccount = acmeAccountService.getOrCreate(organizationId, acmeAccountHandle);
        List<String> certificateDomains = dnsValidationDomainService
                .buildCertificateDomains(domain, wildcardPrimary, sanDomains);

        // Stage key on first attempt; read it back on resume so finalize sees the SAME
        // public key the CA pinned to the order. A regenerated key would mismatch.
        CsrKeyPairService.CsrKeyPairResult csrResult;
        String privateKeyKvPath;
        if (resumeCheckpoint == null || resumeCheckpoint.privateKeyKvPath() == null) {
            csrResult = csrKeyPairService.generateCsrAndKeyPair(
                    certificateDomains.get(0),
                    certificateDomains.size() > 1 ? certificateDomains.subList(1, certificateDomains.size()) : List.of());
            privateKeyKvPath = keyStagingHelper.stage(certificateXref,
                    csrResult.privateKeyPem(), csrResult.csrPem());
        } else {
            com.certping.agent.ssl.KeyStagingHelper.Staged staged =
                    keyStagingHelper.read(resumeCheckpoint.privateKeyKvPath());
            csrResult = new CsrKeyPairService.CsrKeyPairResult(
                    csrPemToDer(staged.csrPem()), staged.csrPem(), staged.privateKeyPem());
            privateKeyKvPath = resumeCheckpoint.privateKeyKvPath();
            log.info("LE resume: read staged key from {}", privateKeyKvPath);
        }

        return issueCore(acmeAccount, certificateXref, domain, certificateDomains,
                csrResult.csrDer(), csrResult.privateKeyPem(), rootDnsProvider, sanDnsProviders,
                resumeCheckpoint, privateKeyKvPath, previousCertSecretHandle, finalPropagationWait, recorder);
    }

    /**
     * Issues using a CSR supplied externally (e.g. Akamai CPS). Private key stays
     * with the caller; only the chain is stored in KV.
     */
    public IssuanceResult issueWithExternalCsr(
            String organizationId,
            String certificateXref,
            String domain,
            boolean wildcardPrimary,
            List<String> sanDomains,
            DnsProvider rootDnsProvider,
            Map<String, DnsProvider> sanDnsProviders,
            String acmeAccountHandle,
            String externalCsrPem,
            boolean finalPropagationWait) {
        return issueWithExternalCsr(organizationId, certificateXref, domain, wildcardPrimary, sanDomains,
                rootDnsProvider, sanDnsProviders, acmeAccountHandle, externalCsrPem, finalPropagationWait,
                null, CheckpointRecorder.NONE);
    }

    /** Issues from a CSR whose key the customer holds; with a recorder a retry resumes from the recorded order. */
    public IssuanceResult issueWithExternalCsr(
            String organizationId,
            String certificateXref,
            String domain,
            boolean wildcardPrimary,
            List<String> sanDomains,
            DnsProvider rootDnsProvider,
            Map<String, DnsProvider> sanDnsProviders,
            String acmeAccountHandle,
            String externalCsrPem,
            boolean finalPropagationWait,
            com.certping.agent.exception.IssuanceCheckpoint resumeCheckpoint,
            CheckpointRecorder recorder) {

        log.info("LE external-CSR issuance started: organizationId={}, domain={}, xref={}, resumeStep={}",
                organizationId, domain, certificateXref, resumeCheckpoint == null ? "none" : resumeCheckpoint.step());
        AcmeAccountResult acmeAccount = acmeAccountService.getOrCreate(organizationId, acmeAccountHandle);
        List<String> certificateDomains = dnsValidationDomainService
                .buildCertificateDomains(domain, wildcardPrimary, sanDomains);
        return issueCore(acmeAccount, certificateXref, domain, certificateDomains,
                csrPemToDer(externalCsrPem), null, rootDnsProvider, sanDnsProviders,
                resumeCheckpoint, null, null, finalPropagationWait, recorder);
    }

    /**
     * Core ACME issuance: order creation, DNS-01 challenges, order finalization, KV
     * store.
     *
     * @param privateKeyPem null when the private key is held externally; chain is
     *                      stored without it.
     */
    private IssuanceResult issueCore(
            AcmeAccountResult acmeAccount,
            String certificateXref,
            String domain,
            List<String> certificateDomains,
            byte[] csrDer,
            String privateKeyPem,
            DnsProvider rootDnsProvider,
            Map<String, DnsProvider> sanDnsProviders,
            com.certping.agent.exception.IssuanceCheckpoint resumeCheckpoint,
            String privateKeyKvPath,
            String previousCertSecretHandle,
            boolean finalPropagationWait,
            CheckpointRecorder recorder) {

        // Mutable local state — every Retryable thrown past ORDER_CREATED carries this map
        // back to the listener so the next attempt's processor reads it from the message.
        // Null on the external-CSR path (Akamai) where checkpointing doesn't apply.
        com.certping.agent.exception.IssuanceCheckpoint state = privateKeyKvPath == null && recorder == CheckpointRecorder.NONE && resumeCheckpoint == null
                ? null
                : (resumeCheckpoint != null
                    ? resumeCheckpoint
                    : new com.certping.agent.exception.IssuanceCheckpoint(
                            "LETS_ENCRYPT",
                            com.certping.agent.exception.IssuanceCheckpoint.Step.CSR_GENERATED,
                            null, null, privateKeyKvPath));

        DnsTxtWorkflowService.TxtWorkflowResult txtWorkflow = null;
        try {
            Session session = new Session(properties.getAcme().getDirectoryUrl());
            Login login = session.login(acmeAccount.accountLocation(), acmeAccount.keyPair());
            Account account = login.getAccount();

            Order order;
            if (resumeCheckpoint != null && resumeCheckpoint.reached(
                    com.certping.agent.exception.IssuanceCheckpoint.Step.ORDER_CREATED)
                    && resumeCheckpoint.orderRef() != null) {
                // RESUME: bindOrder reattaches to the existing order URL — zero LE
                // quota cost, doesn't even make an HTTP call until we touch the order.
                order = login.bindOrder(new java.net.URL(resumeCheckpoint.orderRef()));
                log.info("LE resume: bound to existing order {} (skipping newOrder)",
                        resumeCheckpoint.orderRef());
            } else {
                order = createOrderWithRetry(account, certificateDomains, certificateXref, previousCertSecretHandle);
                // Real LE always returns a Location header; some test mocks don't stub it.
                // If null, leave the checkpoint at CSR_GENERATED — next retry just won't
                // benefit from bindOrder. Safe; just less efficient.
                if (state != null && order.getLocation() != null) {
                    state = state.withOrderRef(order.getLocation().toString(),
                            acmeAccount.accountLocation().toString());
                    recorder.recordAnswered(state);
                    log.info("LE order created for domain={}, orderUrl={}", domain, state.orderRef());
                } else {
                    log.info("LE order created for domain={}", domain);
                }
            }

            // Probe the order's actual server-side state before we do any DNS work.
            // LE deduplicates new-order calls for the same (account, identifier set) in
            // a short window — a retry that follows a partial prior attempt can be handed
            // an order URL already past `pending`. If it's already VALID, the cert is
            // minted and we go straight to chain download; doing the normal pending flow
            // would call finalize on a valid order and hit:
            //   "Order's status (\"valid\") is not acceptable for finalization"
            Status entryStatus = refreshOrderStatus(order, domain);
            log.info("LE order entry status={} for domain={}", entryStatus, domain);
            if (entryStatus == Status.INVALID) {
                throw new PermanentAgentException("ACME_ORDER_INVALID",
                        "LE order is in INVALID state for " + domain + " — cannot proceed");
            }
            boolean skipChallengeAndFinalize =
                    entryStatus == Status.VALID || entryStatus == Status.PROCESSING;

            if (entryStatus == Status.READY) {
                // Every authorization is already valid (the CA reused earlier ones): no DNS
                // work and no challenges, straight to finalize.
                log.info("LE order already READY for domain={}; skipping challenges, finalizing", domain);
                executeOrderWithRetry(order, csrDer);
                waitForOrderValid(order, domain);
            } else if (!skipChallengeAndFinalize) {
                // Real Let's Encrypt reuses authorizations that are still valid; only the
                // PENDING ones need a TXT record and a challenge.
                List<Authorization> pendingAuthorizations = pendingAuthorizations(order, domain);
                List<DnsTxtWorkflowService.TxtRecordRequest> requests = new ArrayList<>();

                for (Authorization auth : pendingAuthorizations) {
                    Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE)
                            .map(ch -> (Dns01Challenge) ch)
                            .orElseThrow(() -> new PermanentAgentException("ACME_NO_DNS_CHALLENGE",
                                    "No DNS-01 challenge for auth: " + auth.getIdentifier().getDomain()));

                    String authDomain = auth.getIdentifier().getDomain();
                    String recordName = "_acme-challenge." + authDomain;
                    String recordValue = challenge.getDigest();

                    requests.add(new DnsTxtWorkflowService.TxtRecordRequest(authDomain, recordName, recordValue));
                }

                if (!requests.isEmpty()) {
                    txtWorkflow = dnsTxtWorkflowService.addTxtRecordsForResumableChallenge(requests, domain,
                            rootDnsProvider, sanDnsProviders, finalPropagationWait);
                }

                for (Authorization auth : pendingAuthorizations) {
                    Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE)
                            .map(ch -> (Dns01Challenge) ch)
                            .orElseThrow(() -> new PermanentAgentException("ACME_NO_DNS_CHALLENGE",
                                    "No DNS-01 challenge for auth: " + auth.getIdentifier().getDomain()));
                    String authDomain = auth.getIdentifier().getDomain();
                    triggerAndWaitForChallenge(challenge, authDomain);
                    Status authorizationStatus;
                    try {
                        authorizationStatus = AcmePollingSupport.requireValidAuthorization(
                                auth, authDomain, properties.getAcme().getChallenge(), log);
                    } catch (AcmeException e) {
                        throw new TransientAgentException("ACME_CHALLENGE_FAILED",
                                "Authorization did not become VALID after "
                                        + properties.getAcme().getChallenge().getMaxAttempts()
                                        + " attempts for domain " + authDomain,
                                e);
                    }
                    if (authorizationStatus != Status.VALID) {
                        throw new TransientAgentException("ACME_CHALLENGE_FAILED",
                                "Authorization did not become VALID after "
                                        + properties.getAcme().getChallenge().getMaxAttempts()
                                        + " attempts for domain " + authDomain + " - status: " + authorizationStatus);
                    }
                }

                executeOrderWithRetry(order, csrDer);
                waitForOrderValid(order, domain);
            } else if (entryStatus == Status.PROCESSING) {
                // PROCESSING: server is finalising; just wait for VALID.
                waitForOrderValid(order, domain);
            }
            // entryStatus == VALID: cert already minted, skip straight to chain download.

            if (state != null) {
                state = state.withStep(
                        com.certping.agent.exception.IssuanceCheckpoint.Step.ORDER_FINALIZED);
            }

            Certificate cert = order.getCertificate();
            List<X509Certificate> chain = downloadCertificateChainWithRetry(cert, domain);
            X509Certificate leaf = chain.get(0);

            String chainPem = buildChainPem(chain);
            String bundle = privateKeyPem != null ? chainPem + "\n" + privateKeyPem : chainPem;
            String certSecretHandle = secretStore.create(certificateXref, bundle);
            String certSecretHandleWithVersion = privateKeyPem == null ? certSecretHandle : null;
            log.info("LE cert stored at {}", certSecretHandle);

            // Terminal success — purge the staging slot. Best-effort; if delete fails we
            // log and continue (the slot then stays in the store). NEVER fail the issuance
            // because we couldn't tidy up.
            if (privateKeyKvPath != null) {
                keyStagingHelper.purge(privateKeyKvPath);
            }

            String serial = leaf.getSerialNumber().toString(16).toUpperCase();
            String fingerprint = sha256Fingerprint(leaf);
            OffsetDateTime validFrom = leaf.getNotBefore().toInstant().atOffset(ZoneOffset.UTC);
            OffsetDateTime validTo = leaf.getNotAfter().toInstant().atOffset(ZoneOffset.UTC);
            String issuer = leaf.getIssuerX500Principal().getName();
            CertificateMetadata metadata = CertificateMetadataExtractor.fromLeaf(leaf);

            log.info("LE issuance complete: domain={}, serial={}, validTo={}", domain, serial, validTo);
            return new IssuanceResult(
                    certSecretHandle, certSecretHandleWithVersion, acmeAccount.acmeAccountHandle(),
                    serial, fingerprint, validFrom, validTo, issuer, null,
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
                    CertType.DV).withKeyCustody(KeyCustody.ofStoredKey(privateKeyPem));

        } catch (AcmeNetworkException e) {
            throw attachCheckpoint(new TransientAgentException("ACME_NETWORK_ERROR",
                    "Network error during LE issuance: " + e.getMessage(), e), state);
        } catch (AcmeRateLimitedException e) {
            throw attachCheckpoint(toRetryable("LE issuance", domain, e), state);
        } catch (AcmeException e) {
            // AcmeServerException carries the HTTP status (e.g. 503 with Retry-After) — classify
            // before falling through to the permanent path so transient throttle/maintenance
            // signals re-enqueue rather than poisoning the cert request.
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "CA_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw attachCheckpoint(rl.get().toRetryable("LE issuance", domain, e), state);
            }
            if (hasNetworkCause(e)) {
                throw attachCheckpoint(new TransientAgentException("ACME_NETWORK_ERROR",
                        "Network error during LE issuance: " + e.getMessage(), e), state);
            }
            throw new PermanentAgentException("ACME_ISSUANCE_FAILED",
                    "ACME issuance failed for " + domain + ": " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw attachCheckpoint(new TransientAgentException("ACME_INTERRUPTED",
                    "LE issuance interrupted: " + e.getMessage(), e), state);
        } catch (PermanentAgentException e) {
            throw e;
        } catch (TransientAgentException | RetryableAgentException e) {
            throw attachCheckpoint(e, state);
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "CA_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw attachCheckpoint(rl.get().toRetryable("LE issuance", domain, e), state);
            }
            if (hasNetworkCause(e)) {
                // For example an HTTP timeout while polling the order: the CA may be slow, the
                // request is still good, so redeliver instead of dead-lettering.
                throw attachCheckpoint(new TransientAgentException("ACME_NETWORK_ERROR",
                        "Network error during LE issuance: " + e.getMessage(), e), state);
            }
            throw new PermanentAgentException("ACME_ISSUANCE_FAILED",
                    "Unexpected runtime error during LE issuance for " + domain + ": "
                            + e.getClass().getSimpleName() + " - " + e.getMessage(),
                    e);
        } finally {
            cleanupDnsTxtRecords(txtWorkflow, domain);
        }
    }

    /** Attaches the current checkpoint to a Retryable so the listener stamps {@code Checkpoint.*}
     *  on the re-enqueued message. No-op for non-Retryable types (Transient + Permanent
     *  don't carry checkpoints — Transient is blind backoff, Permanent dead-letters). */
    private RuntimeException attachCheckpoint(RuntimeException e,
                                              com.certping.agent.exception.IssuanceCheckpoint state) {
        if (state == null || !state.reached(
                com.certping.agent.exception.IssuanceCheckpoint.Step.ORDER_CREATED)) {
            // Before ORDER_CREATED there's nothing to resume past — let the next attempt
            // re-run from scratch. Avoids carrying a half-baked checkpoint that points at
            // nothing useful.
            return e;
        }
        if (e instanceof RetryableAgentException re) {
            return re.withCheckpoint(state);
        }
        return e;
    }

    private byte[] csrPemToDer(String csrPem) {
        String b64 = csrPem
                .replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                .replace("-----END CERTIFICATE REQUEST-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(b64);
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    private Order createOrderWithRetry(Account account, List<String> domains, String certificateXref,
                                       String previousCertSecretHandle)
            throws AcmeException, InterruptedException {
        // ARI hint: prefer the supplied previousCertSecretHandle (renewal — points at the OLD cert).
        // Fall back to deriving from the current xref only as a defensive default for callers
        // that haven't been updated; on issuance this misses (no prior cert exists yet, by design).
        String ariPath = (previousCertSecretHandle != null && !previousCertSecretHandle.isBlank())
                ? previousCertSecretHandle
                : inferCurrentCertSecretHandle(certificateXref);
        X509Certificate existingCert = loadExistingCertForAri(ariPath);
        try {
            OrderBuilder builder = account.newOrder().domains(domains);
            if (existingCert != null) {
                try {
                    builder.replaces(existingCert);
                } catch (UnsupportedOperationException e) {
                    log.warn("LE ARI unsupported by ACME server, continuing without replaces: {}", e.getMessage());
                }
            }
            return builder.create();
        } catch (AcmeRateLimitedException e) {
            // No in-thread sleep: signal the listener to re-schedule the message on the agent's
            // queue (a delayed retry) so the worker thread is freed immediately.
            throw toRetryable("order creation", domainLabel(domains), e);
        } catch (AcmeServerException e) {
            if (existingCert != null) {
                // replaces (RFC 9773) is only a hint. If the CA rejects an order that carries it,
                // for any reason (duplicate replacement, certificate id it cannot match), the
                // renewal must still go ahead, so try once more without it.
                log.warn("ACME order with replaces rejected ({}), retrying without replaces",
                        describeReplacementError(e));
                return createOrderWithoutReplacement(account, domains);
            }
            throw e;
        }
    }

    private Order createOrderWithoutReplacement(Account account, List<String> domains)
            throws AcmeException {
        try {
            return account.newOrder().domains(domains).create();
        } catch (AcmeRateLimitedException e) {
            throw toRetryable("fallback order creation", domainLabel(domains), e);
        }
    }

    /** True when an I/O error or a timeout is somewhere in the cause chain. */
    public static boolean hasNetworkCause(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause() == t ? null : t.getCause()) {
            if (t instanceof java.io.IOException
                    || t instanceof java.io.UncheckedIOException
                    || t instanceof java.util.concurrent.TimeoutException
                    || t instanceof AcmeNetworkException) {
                return true;
            }
        }
        return false;
    }

    private static String describeReplacementError(AcmeServerException e) {
        String message = e.getMessage();
        return message == null ? e.getClass().getSimpleName() : message;
    }

    /**
     * The order's authorizations that still need a DNS-01 challenge. VALID ones (reused by the
     * CA) are skipped; INVALID, DEACTIVATED, EXPIRED or REVOKED ones can never become valid on
     * this order, so the issuance fails clearly instead of triggering a challenge the CA rejects.
     * A status the CA has not reported yet is treated as PENDING.
     */
    static List<Authorization> pendingAuthorizations(Order order, String domain) {
        List<Authorization> pending = new ArrayList<>();
        for (Authorization auth : order.getAuthorizations()) {
            Status status = auth.getStatus();
            String authDomain = auth.getIdentifier().getDomain();
            if (status == Status.VALID) {
                log.info("LE authorization for {} is already VALID; skipping its challenge", authDomain);
                continue;
            }
            if (status == Status.INVALID || status == Status.DEACTIVATED || status == Status.EXPIRED
                    || status == Status.REVOKED) {
                throw new PermanentAgentException("ACME_AUTHORIZATION_" + status.name(),
                        "LE authorization for " + authDomain + " is " + status
                                + " and cannot be completed; the order for " + domain + " must be recreated");
            }
            pending.add(auth);
        }
        return pending;
    }

    private void triggerAndWaitForChallenge(Dns01Challenge challenge, String domain)
            throws AcmeException, InterruptedException {
        AgentProperties.ChallengeProperties cfg = properties.getAcme().getChallenge();

        challenge.trigger();
        log.info("Challenge triggered for domain {}", domain);

        Status challengeStatus = challenge.getStatus();
        if (challengeStatus != Status.VALID && challengeStatus != Status.INVALID) {
            try {
                challengeStatus = AcmePollingSupport.waitForChallengeCompletion(challenge, cfg);
            } catch (AcmeException e) {
                throw new TransientAgentException("ACME_CHALLENGE_FAILED",
                        "DNS-01 challenge did not become VALID after " + cfg.getMaxAttempts()
                                + " attempts for domain " + domain,
                        e);
            }
        }

        log.debug("Challenge status={} for domain {}", challengeStatus, domain);
        if (challengeStatus == Status.INVALID) {
            // INVALID is Let's Encrypt's final verdict — re-running the same order yields the same
            // result, so fail permanently (user must fix DNS) instead of burning the retry budget.
            String problem = AcmePollingSupport.problemOf(challenge);
            log.warn("DNS-01 challenge for {} was rejected (INVALID){}", domain, problem);
            throw new PermanentAgentException("ACME_CHALLENGE_INVALID",
                    "DNS-01 challenge was rejected (INVALID) by Let's Encrypt for domain " + domain + problem
                            + "; verify the _acme-challenge TXT record and DNS configuration");
        }
        if (challengeStatus != Status.VALID) {
            throw new TransientAgentException("ACME_CHALLENGE_FAILED",
                    "DNS-01 challenge did not become VALID after " + cfg.getMaxAttempts()
                            + " attempts for domain " + domain + " - status: " + challengeStatus);
        }
        log.info("Challenge VALID for domain {}", domain);
    }

    /** Forces a POST-as-GET on the order URL so {@link Order#getStatus()} reflects the
     *  server's current state, not whatever was cached from new-order. acme4j caches the
     *  status from the last response; for an order we got handed back via LE's new-order
     *  dedup that cached value may be stale ("pending" while server is already "valid").
     *  Failures here are non-fatal — fall back to the cached status. */
    private Status refreshOrderStatus(Order order, String domain) {
        try {
            order.fetch();
        } catch (Exception e) {
            log.warn("Failed to refresh LE order status for {}: {} — using cached state",
                    domain, e.getMessage());
        }
        return order.getStatus();
    }

    private void executeOrderWithRetry(Order order, byte[] csrDer)
            throws AcmeException, InterruptedException {
        try {
            order.execute(csrDer);
        } catch (AcmeRateLimitedException e) {
            throw toRetryable("order execute", "unknown-domain", e);
        } catch (AcmeServerException e) {
            // LE deduplicates /acme/new-order for same (account, identifiers) inside a
            // short window. A prior attempt that already finalised but failed downstream
            // (KV write, chain download, pod crash) leaves the order in `valid` at LE;
            // newOrder on the retry hands us back that same order URL. Finalize on a
            // `valid` order is rejected with this exact phrase — but the cert IS minted
            // and downloadable, so treat as soft success and fall through to
            // order.getCertificate() / chain download.
            if (isOrderAlreadyFinalised(e)) {
                log.warn("LE order already in `valid` state (prior attempt finalised) — "
                        + "skipping finalize, proceeding to chain download");
                return;
            }
            throw e;
        }
    }

    private static boolean isOrderAlreadyFinalised(AcmeServerException e) {
        String msg = e.getMessage();
        return msg != null && msg.toLowerCase(java.util.Locale.ROOT)
                .contains("status (\"valid\") is not acceptable for finalization");
    }

    private List<X509Certificate> downloadCertificateChainWithRetry(Certificate cert, String domain) {
        try {
            return cert.getCertificateChain();
        } catch (RuntimeException e) {
            Optional<AcmeRateLimitedException> nestedRateLimit = findRateLimitInCauseChain(e);
            if (nestedRateLimit.isPresent()) {
                throw toRetryable("certificate chain download", domain, nestedRateLimit.get());
            }
            throw e;
        }
    }

    /**
     * Builds the {@link RetryableAgentException} the listener uses to re-schedule the message on
     * the agent's queue, so no thread sleeps through the wait. When LE supplies a
     * {@code Retry-After} we honor it exactly (the listener caps it); when it doesn't, we leave
     * {@code retryAfter} null so the listener falls back to its blind backoff curve.
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

    private String domainLabel(List<String> domains) {
        if (domains == null || domains.isEmpty()) {
            return "unknown-domain";
        }
        return domains.get(0);
    }

    private Optional<AcmeRateLimitedException> findRateLimitInCauseChain(Throwable throwable) {
        Throwable cursor = throwable;
        while (cursor != null) {
            if (cursor instanceof AcmeRateLimitedException rateLimitedException) {
                return Optional.of(rateLimitedException);
            }
            cursor = cursor.getCause();
        }
        return Optional.empty();
    }

    private void cleanupDnsTxtRecords(DnsTxtWorkflowService.TxtWorkflowResult txtWorkflow, String domain) {
        if (txtWorkflow == null || txtWorkflow.cleanupEntries() == null || txtWorkflow.cleanupEntries().isEmpty()) {
            return;
        }
        try {
            dnsTxtCleanupService.cleanup(txtWorkflow.cleanupEntries());
        } catch (RuntimeException e) {
            log.warn("Failed to cleanup DNS TXT records for {}: {}", domain, e.getMessage());
        }
    }

    private X509Certificate loadExistingCertForAri(String currentCertSecretHandle) {
        if (currentCertSecretHandle == null || currentCertSecretHandle.isBlank()) {
            return null;
        }

        try {
            String bundle = secretStore.read(currentCertSecretHandle);
            if (bundle == null || bundle.isBlank()) {
                return null;
            }
            X509Certificate existingCert = extractLeafCert(bundle);
            log.info("LE ARI enabled using current cert at {}", currentCertSecretHandle);
            return existingCert;
        } catch (Exception e) {
            // First-issuance is the common case: no prior cert exists to ARI-replace,
            // so KV legitimately returns "Secret not found". That's not a warning.
            String msg = e.getMessage() == null ? "" : e.getMessage();
            boolean notFound = msg.contains("Secret not found")
                    || msg.contains("SecretNotFound")
                    || msg.contains("Status code 404");
            if (notFound) {
                log.debug("LE ARI not applicable (no prior cert at {}): first issuance", currentCertSecretHandle);
            } else {
                log.warn("LE ARI skipped, could not load current cert from {}: {}",
                        currentCertSecretHandle, msg);
            }
            return null;
        }
    }

    private String inferCurrentCertSecretHandle(String certificateXref) {
        String kvUri = properties.getKeyvault().getUri();
        if (kvUri == null || kvUri.isBlank() || certificateXref == null || certificateXref.isBlank()) {
            return null;
        }
        String normalizedKvUri = kvUri.endsWith("/") ? kvUri.substring(0, kvUri.length() - 1) : kvUri;
        return normalizedKvUri + "/secrets/" + certificateXref;
    }

    private X509Certificate extractLeafCert(String bundle) throws Exception {
        int start = bundle.indexOf("-----BEGIN CERTIFICATE-----");
        int endMarkerStart = bundle.indexOf("-----END CERTIFICATE-----");
        if (start < 0 || endMarkerStart < 0 || endMarkerStart <= start) {
            throw new IllegalArgumentException("No PEM certificate found in bundle");
        }

        int end = endMarkerStart + "-----END CERTIFICATE-----".length();
        String firstPem = bundle.substring(start, end);
        byte[] der = Base64.getDecoder().decode(firstPem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", ""));

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    private void waitForOrderValid(Order order, String domain)
            throws AcmeException, InterruptedException {
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
            sw.write(java.util.Base64.getMimeEncoder(64, new byte[] { '\n' })
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
