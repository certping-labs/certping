// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.message.ScepCertIssuedResponse;
import com.certping.agent.model.message.ScepCertRequestedResponse;
import com.certping.agent.model.message.ScepCertResultResponse;
import com.certping.agent.scep.ca.CaException;
import com.certping.agent.scep.ca.IssuedCertificate;
import com.certping.agent.scep.intune.IntuneScepValidator;
import com.certping.agent.scep.intune.ScepValidationResult;
import com.certping.agent.ssl.CertificateMetadata;
import com.certping.agent.ssl.CertificateMetadataExtractor;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import com.certping.agent.util.MdcContextPropagator;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Orchestrates a SCEP {@code PKIOperation}: parse and verify, validate the challenge with Intune,
 * sign at the CA backend, and return a signed {@code CertRep}. Always returns a signed CertRep
 * (SUCCESS / FAILURE / PENDING) at HTTP 200; only transport-level problems throw (see the advice).
 */
@Slf4j
@RequiredArgsConstructor
public class ScepService {

    private final ScepEndpointRegistry registry;
    private final PkiMessageCodec codec;
    private final IntuneScepValidator intune;
    private final ScepTransactionStore transactions;
    private final AgentMessageSender messageSender;
    private final Clock clock;
    private final ScepProfileHintResolver profileHints;

    /**
     * The {@code SCEP_CERT_ISSUED} publish runs here, off the request thread. The underlying
     * {@code MessageSender.sendMessage} can wait on request timeouts and throttling retries when the
     * server is slow or unreachable; doing it inline would hang the device's CertRep response (the cert is already
     * signed) until the client times out. Bounded queue + a drop-and-log rejection handler means a
     * server outage can never block or fail an enrolment — at worst a metadata publish is dropped.
     */
    private final ExecutorService publishExecutor = new ThreadPoolExecutor(
            1, 2, 60L, TimeUnit.SECONDS, new LinkedBlockingQueue<>(200),
            runnable -> {
                Thread thread = new Thread(runnable, "scep-cert-issued-publish");
                thread.setDaemon(true);
                return thread;
            },
            (runnable, executor) -> log.warn(
                    "SCEP_CERT_ISSUED publish dropped — publisher saturated (server slow or unreachable)"));

    @PreDestroy
    void stopPublisher() {
        // Queued tasks carry metadata for certificates the CA has already signed and the device
        // already holds; dropping them on a rolling restart would lose the inventory record with
        // no way to re-derive it. Drain briefly, then force.
        publishExecutor.shutdown();
        try {
            if (!publishExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                log.warn("SCEP publisher did not drain within 5s — {} queued publish(es) dropped",
                        publishExecutor.shutdownNow().size());
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            publishExecutor.shutdownNow();
        }
    }

    public BinaryResponse pkiOperation(String endpointId, byte[] der) {
        ResolvedEndpoint endpoint = registry.resolve(endpointId);
        // Retry-dedup must be keyed by the source, not the raw route: with the 'default'
        // compatibility alias live, the same transaction replayed on the alias and on the source
        // URL is one enrollment, and must never sign twice or dodge the CSR-conflict check.
        String transactionScope = endpoint.connectionProfileRef();
        ScepRequest request;
        try {
            request = codec.parse(der, endpoint.raPrivateKey());
        } catch (Exception e) {
            throw new BadPkiMessageException(e);
        }
        // A SCEP request arrives from a device with no correlation id of its own. The transaction
        // id is client-generated, stable across retries, sent to Intune, and carried into all three
        // server messages — so it is the one value that joins the device, the CA, Intune and
        // the server. TraceMdcFilter clears it when the request ends.
        MDC.put("correlationId", request.transactionId());

        return transactions.execute(
                transactionScope, request.transactionId(), request.csrFingerprint(),
                () -> switch (request.messageType()) {
                    case ScepConstants.MSG_PKCS_REQ, ScepConstants.MSG_RENEWAL_REQ ->
                            enrol(endpoint, transactionScope, request);
                    case ScepConstants.MSG_CERT_POLL -> poll(endpoint, request);
                    default -> fail(endpoint, request, ScepConstants.FAIL_BAD_REQUEST,
                            "unsupported messageType");
                });
    }

    public BinaryResponse getCaCaps(String endpointId) {
        String caps = String.join("\r\n", registry.resolve(endpointId).caps());
        return new BinaryResponse("text/plain", caps.getBytes(StandardCharsets.US_ASCII));
    }

    public BinaryResponse getCaCert(String endpointId) {
        try {
            ResolvedEndpoint endpoint = registry.resolve(endpointId);
            List<X509Certificate> caChain = endpoint.caChain();
            if (caChain.isEmpty()) {
                // No separate issuer available — publish the RA cert alone as a single DER cert.
                return new BinaryResponse(ScepConstants.CT_CA_CERT, endpoint.raCert().getEncoded());
            }
            // Separate RA: PKCS#7 with the RA cert (device encrypts to it) + the issuing CA chain.
            List<X509Certificate> bundle = new ArrayList<>();
            bundle.add(endpoint.raCert());
            bundle.addAll(caChain);
            return new BinaryResponse(ScepConstants.CT_CA_RA_CERT, codec.certsOnlyPkcs7(bundle));
        } catch (Exception e) {
            throw new IllegalStateException("GetCACert failed", e);
        }
    }

    public boolean supportsRollover(String endpointId) {
        return registry.resolve(endpointId).caps().contains("GetNextCACert");
    }

    public byte[] getNextCaCert(String endpointId) {
        throw new IllegalStateException("rollover material not configured for " + endpointId);
    }

    // ---- internals ------------------------------------------------------------------------------

    private BinaryResponse enrol(ResolvedEndpoint endpoint, String transactionScope, ScepRequest request) {
        OffsetDateTime requestedAt = now();
        try {
            // This codec implements CMS KeyTransRecipientInfo, which requires an encryption-capable
            // client key (RSA in our supported set). RFC 8894 uses PasswordRecipientInfo for ECDSA
            // and DSA clients. Reject those before the CA signs so we never create an orphaned
            // certificate that cannot be delivered in the CertRep.
            if (!"RSA".equalsIgnoreCase(request.deviceCertificate().getPublicKey().getAlgorithm())) {
                return fail(endpoint, request, ScepConstants.FAIL_BAD_ALG,
                        "client certificate key is not supported for CertRep encryption");
            }
            // Audit that an initial enrollment arrived and parsed, before validation decides anything.
            if (request.messageType() == ScepConstants.MSG_PKCS_REQ) {
                scheduleRequested(endpoint, request, requestedAt);
            }
            ScepValidationResult validation = ScepValidationResult.absent();
            X509Certificate priorCertificate = null;
            if (request.messageType() == ScepConstants.MSG_PKCS_REQ) {
                validation = intune.validate(endpoint, request.transactionId(), request.csrDerBase64());
                if (validation == null) {
                    throw new ChallengeValidationException("challenge validator returned no result");
                }
                if (!validation.hasIdentifier()) {
                    String challengeDeviceId = extractChallengeDeviceId(request);
                    if (challengeDeviceId != null) {
                        validation = classifyIdentifier(request, challengeDeviceId);
                    }
                }
            } else {
                priorCertificate = ScepRenewalAuthenticator.authenticate(endpoint, request);
                endpoint.caBackend().assertRenewalAllowed(priorCertificate);
            }
            OffsetDateTime validatedAt = now();

            ScepProfileHintResolver.ScepProfileHint hint = profileHints.resolve(endpoint);
            IssuedCertificate issued = endpoint.caBackend().sign(request.csr(), hint.validity());
            OffsetDateTime issuedAt = now();
        // Synchronous and unconditional: the metadata publish below is best-effort and can be
        // dropped under saturation, which would otherwise leave a certificate the device holds
        // with no record of it anywhere on the agent.
        log.info("SCEP certificate issued: profile={} txn={} serial={} type={} durationMs={}",
                endpoint.connectionProfileRef(), request.transactionId(),
                issued.leaf().getSerialNumber().toString(16),
                priorCertificate == null ? "INITIAL" : "RENEWAL",
                java.time.Duration.between(validatedAt, issuedAt).toMillis());
            try {
                byte[] certRep;
                try {
                    certRep = codec.buildSuccess(
                            request, issued.chain(), endpoint.raCert(), endpoint.raPrivateKey());
                } catch (Exception e) {
                    throw new IllegalStateException("failed to build SUCCESS CertRep", e);
                }
                BinaryResponse response = new BinaryResponse(ScepConstants.CT_PKI_MESSAGE, certRep);
                transactions.record(transactionScope, request, response);

                // Only a PKCSReq carries an Intune-issued challenge/transaction; a RenewalReq is
                // authenticated by the current certificate and is not a transaction Intune owns, so it
                // must not receive a SendSuccessNotification (mirrors the notifyFailure placement).
                if (request.messageType() == ScepConstants.MSG_PKCS_REQ) {
                    X509Certificate leaf = issued.leaf();
                    String issuerDn = leaf.getIssuerX500Principal().getName();
                    try {
                        intune.notifySuccess(endpoint, request.transactionId(), request.csrDerBase64(),
                                digest(leaf, "SHA-1"), leaf.getSerialNumber().toString(16),
                                iso(leaf.getNotAfter()), issuerDn, issuerDn, issuerDn);
                    } catch (Exception exception) {
                        // The CA has already issued the certificate. Intune notification failure must not
                        // suppress the independent server inventory message or the device's successful CertRep.
                        log.error("SCEP certificate issued but Intune success notification failed txn={}: {}",
                                request.transactionId(), exception.getClass().getSimpleName());
                    }
                }
                return response;
            } finally {
                schedulePublishSafely(endpoint, request, issued, validation, priorCertificate,
                        hint.providerProfileId(),
                        new EnrollmentTimeline(requestedAt, validatedAt, issuedAt, now()));
            }

        } catch (ChallengeValidationException e) {
            // Intune already recorded this rejection inside ValidateRequest (and a renewal check is
            // ours, not Intune's), so we must not send a SendFailureNotification for it.
            if (request.messageType() == ScepConstants.MSG_PKCS_REQ) {
                scheduleResult(endpoint, request, "REJECTED", "INTUNE_VALIDATION", false,
                        "CHALLENGE_REJECTED", e.getMessage());
            }
            return fail(endpoint, request, ScepConstants.FAIL_BAD_MESSAGE_CHECK, e.getMessage());
        } catch (IntuneUnavailableException e) {
            // The device gets HTTP 503 (see the advice) and will retry the same transaction. The
            // SCEP_CERT_REQUESTED shell was already published, so record a retryable outcome
            // instead of leaving the enrollment dangling as RECEIVED forever.
            if (request.messageType() == ScepConstants.MSG_PKCS_REQ) {
                scheduleResult(endpoint, request, "FAILED", "INTUNE_VALIDATION", true,
                        "INTUNE_UNAVAILABLE", e.getMessage());
            }
            throw e;
        } catch (CaUnavailableException e) {
            if (request.messageType() == ScepConstants.MSG_PKCS_REQ) {
                scheduleResult(endpoint, request, "FAILED", "CA_SIGNING", true,
                        "CA_UNAVAILABLE", e.getMessage());
            }
            throw e;
        } catch (CaException e) {
            // The challenge already validated but the CA refused. This transaction is Intune's, so it
            // is the one failure path that should report back to Intune.
            if (request.messageType() == ScepConstants.MSG_PKCS_REQ) {
                notifyFailureQuietly(endpoint, request, 0x80070005L, e.getMessage());
                scheduleResult(endpoint, request, "FAILED", "CA_SIGNING", false,
                        "CA_REJECTED", e.getMessage());
            }
            return fail(endpoint, request, ScepConstants.FAIL_BAD_REQUEST, e.getMessage());
        }
    }


    /**
     * Decides which device identifier to publish and how far it can be trusted.
     *
     * <p>The token's {@code <DeviceId>} element sits <em>outside</em> the signed {@code <Data>}
     * block, so the signature does not cover it and it cannot be trusted on its own. What a live
     * tamper test against the tenant did prove is that Intune binds the <em>CSR subject</em> to the
     * challenge it issued: resubmitting a request whose subject had been altered was rejected with
     * {@code SubjectNameMismatch}. The subject is therefore the trustworthy carrier.
     *
     * <p>Which identifier the subject holds depends on the profile's subject name format —
     * {@code {{DeviceId}}} yields the Intune managed-device id, {@code {{AAD_Device_ID}}} the Entra
     * device id, and the two differ for most devices. The agent does not guess: when the subject
     * matches the token DeviceId the namespace is known to be the managed-device id, otherwise the
     * namespace is left {@code UNKNOWN} and the server resolves it against the identifier
     * namespaces it actually stores for the source.
     */
    private ScepValidationResult classifyIdentifier(ScepRequest request, String challengeDeviceId) {
        String validatedSubject = subjectCommonName(request);
        if (!intune.validatesWithMicrosoft()) {
            // Nothing was proven, so nothing may auto-link. Publish what was seen and no more.
            return ScepValidationResult.asserted(
                    challengeDeviceId, ScepValidationResult.IdentifierType.MANAGED_DEVICE_ID);
        }
        if (challengeDeviceId.equals(validatedSubject)) {
            return ScepValidationResult.microsoftValidated(
                    challengeDeviceId, ScepValidationResult.IdentifierType.MANAGED_DEVICE_ID);
        }
        if (isGuid(validatedSubject)) {
            log.info("SCEP device-id differs from the validated CSR subject — publishing the subject "
                    + "with an undetermined namespace for cert-manager to resolve (txn={})",
                    request.transactionId());
            return ScepValidationResult.microsoftValidated(
                    validatedSubject, ScepValidationResult.IdentifierType.UNKNOWN);
        }
        // No validated identifier to stand behind: the subject is absent or is not an identifier
        // we can resolve (a serial number, a device name). Publish the token value unproven.
        log.info("SCEP device-id not bound to a resolvable validated subject — publishing as ASSERTED "
                + "so it cannot auto-link a device (txn={})", request.transactionId());
        return ScepValidationResult.asserted(
                challengeDeviceId, ScepValidationResult.IdentifierType.MANAGED_DEVICE_ID);
    }

    private static final Pattern GUID = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    private static boolean isGuid(String value) {
        return value != null && GUID.matcher(value).matches();
    }

    /**
     * Lower-cased CN of the CSR subject, or null unless the subject carries exactly one.
     *
     * <p>Flattens every RDN rather than using {@code getRDNs(CN)}: that returns the whole RDN when
     * any component is a CN, and {@code getFirst()} then yields the DER-first component, which for
     * a multi-valued RDN such as {@code CN=<guid>+SERIALNUMBER=XYZ} is not the CN at all. It also
     * cannot see a second CN hiding in the same RDN, which must disqualify the subject.
     */
    private static String subjectCommonName(ScepRequest request) {
        try {
            String commonName = null;
            for (org.bouncycastle.asn1.x500.RDN rdn : request.csr().getSubject().getRDNs()) {
                for (org.bouncycastle.asn1.x500.AttributeTypeAndValue attribute
                        : rdn.getTypesAndValues()) {
                    if (!org.bouncycastle.asn1.x500.style.BCStyle.CN.equals(attribute.getType())) {
                        continue;
                    }
                    if (commonName != null) {
                        return null;   // more than one CN: ambiguous, refuse it
                    }
                    commonName = org.bouncycastle.asn1.x500.style.IETFUtils
                            .valueToString(attribute.getValue());
                }
            }
            return commonName == null ? null
                    : commonName.trim().toLowerCase(java.util.Locale.ROOT);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private BinaryResponse poll(ResolvedEndpoint endpoint, ScepRequest request) {
        // No manual-approval flow configured, so nothing is ever PENDING; an unknown poll is badRequest.
        return fail(endpoint, request, ScepConstants.FAIL_BAD_REQUEST,
                "no pending transaction for this transactionID");
    }

    private BinaryResponse fail(ResolvedEndpoint endpoint, ScepRequest request, int failInfo, String reason) {
        // Intune is deliberately not notified here: fail(...) also serves poll, unsupported message
        // types, unsupported keys, and pre-validation rejects — transactions Intune neither owns nor
        // expects a SendFailureNotification for. The one Intune-owned failure (a CA refusal after the
        // challenge validated) notifies from the enrol catch before calling fail(...).
        log.warn("SCEP FAILURE txn={} failInfo={} reason={}", request.transactionId(), failInfo, reason);
        try {
            byte[] certRep = codec.buildFailure(request, failInfo, endpoint.raCert(), endpoint.raPrivateKey());
            return new BinaryResponse(ScepConstants.CT_PKI_MESSAGE, certRep);
        } catch (Exception e) {
            throw new IllegalStateException("failed to build CertRep FAILURE", e);
        }
    }

    private void notifyFailureQuietly(ResolvedEndpoint endpoint, ScepRequest request,
                                      long hResult, String reason) {
        try {
            intune.notifyFailure(endpoint, request.transactionId(), request.csrDerBase64(), hResult, reason);
        } catch (Exception e) {
            // The CertRep FAILURE still goes to the device; a failed Intune notification must not mask it.
            log.error("Intune failure notification failed txn={}: {}",
                    request.transactionId(), e.getMessage());
        }
    }

    private void schedulePublishSafely(ResolvedEndpoint endpoint, ScepRequest request,
                                       IssuedCertificate issued, ScepValidationResult validation,
                                       X509Certificate priorCertificate,
                                       String providerProfileId,
                                       EnrollmentTimeline timeline) {
        try {
            publishExecutor.execute(MdcContextPropagator.wrap(() -> publishIssued(
                    endpoint, request, issued, validation, priorCertificate, providerProfileId,
                    timeline)));
        } catch (RejectedExecutionException exception) {
            // Issuance already happened. Executor saturation must not turn a valid CertRep into a
            // device-visible failure; the bounded publisher logs and drops this metadata update.
            log.error("SCEP certificate issued but metadata publish could not be scheduled txn={}",
                    request.transactionId());
        }
    }

    private void scheduleRequested(ResolvedEndpoint endpoint, ScepRequest request, OffsetDateTime requestedAt) {
        scheduleOffThread(() -> publishRequested(endpoint, request, requestedAt), request);
    }

    private void scheduleResult(ResolvedEndpoint endpoint, ScepRequest request, String status, String stage,
                                boolean retryable, String errorCode, String errorMessage) {
        scheduleOffThread(
                () -> publishResult(endpoint, request, status, stage, retryable, errorCode, errorMessage),
                request);
    }

    private void scheduleOffThread(Runnable task, ScepRequest request) {
        try {
            publishExecutor.execute(MdcContextPropagator.wrap(task));
        } catch (RejectedExecutionException exception) {
            // Publishing must never turn a device response into a failure; drop and log on saturation.
            log.error("SCEP event publish could not be scheduled txn={}", request.transactionId());
        }
    }

    private void publishRequested(ResolvedEndpoint endpoint, ScepRequest request, OffsetDateTime requestedAt) {
        try {
            messageSender.sendScepCertRequested(ScepCertRequestedResponse.builder()
                    .messageVersion(2)
                    .requestId(request.transactionId())
                    .correlationId(request.transactionId())
                    .organizationId(endpoint.organizationId())
                    .connectionProfileRef(endpoint.connectionProfileRef())
                    .endpointId(endpoint.endpointId())
                    .intuneTransactionId(request.transactionId())
                    .csrFingerprintSha256(request.csrFingerprint())
                    .publicKeyAlgorithm(csrKeyAlgorithm(request))
                    .keySize(csrKeySize(request))
                    .requestedAt(requestedAt.toString())
                    .build());
        } catch (Exception e) {
            log.error("SCEP_CERT_REQUESTED publish failed txn={}: {}", request.transactionId(), e.getMessage());
        }
    }

    private void publishResult(ResolvedEndpoint endpoint, ScepRequest request, String status, String stage,
                               boolean retryable, String errorCode, String errorMessage) {
        try {
            messageSender.sendScepCertResult(ScepCertResultResponse.builder()
                    .messageVersion(2)
                    .requestId(request.transactionId())
                    .correlationId(request.transactionId())
                    .organizationId(endpoint.organizationId())
                    .connectionProfileRef(endpoint.connectionProfileRef())
                    .endpointId(endpoint.endpointId())
                    .intuneTransactionId(request.transactionId())
                    .csrFingerprintSha256(request.csrFingerprint())
                    .status(status)
                    .stage(stage)
                    .retryable(retryable)
                    .errorCode(errorCode)
                    .errorMessage(bounded(errorMessage))
                    .occurredAt(now().toString())
                    .build());
        } catch (Exception e) {
            log.error("SCEP_CERT_RESULT publish failed txn={}: {}", request.transactionId(), e.getMessage());
        }
    }

    private static final Pattern CHALLENGE_DEVICE_ID = Pattern.compile(
            "<DeviceId>\\s*([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                    + "[0-9a-fA-F]{12})\\s*</DeviceId>");
    private static final String CERT_ENROLL_TOKEN = "<CertEnrollToken>";

    /**
     * Extracts the Intune DeviceId from the CertEnrollToken carried (base64) in the CSR
     * challengePassword. Regex over the decoded token is XXE-immune (no XML parser), bounded to a
     * GUID shape, and never logs the challenge. Returns null on any failure so extraction never
     * breaks issuance — the certificate is still delivered, the enrollment is just left unmatched.
     *
     * <p>Deliberately strict: the payload must actually be a {@code CertEnrollToken}, and it must
     * carry exactly one DeviceId. A token with a second one is ambiguous about which device it
     * speaks for, and guessing there is how a certificate ends up on the wrong device.
     */
    private String extractChallengeDeviceId(ScepRequest request) {
        String challengePassword = request.challengePassword();
        if (challengePassword == null || challengePassword.isBlank()) {
            log.warn("SCEP device-id: no challengePassword on the CSR");
            return null;
        }
        String token = decodeChallengeToken(challengePassword);
        if (!token.startsWith(CERT_ENROLL_TOKEN)) {
            log.warn("SCEP device-id: challengePassword is not a CertEnrollToken (challengeLen={})",
                    challengePassword.length());
            return null;
        }
        Matcher matcher = CHALLENGE_DEVICE_ID.matcher(token);
        if (!matcher.find()) {
            log.warn("SCEP device-id: no <DeviceId> found (challengeLen={}, decodedLen={})",
                    challengePassword.length(), token.length());
            return null;
        }
        String deviceId = matcher.group(1);
        if (matcher.find()) {
            log.warn("SCEP device-id: token carries more than one <DeviceId> — refusing to guess");
            return null;
        }
        // Graph reports managedDevice ids in lower case and both sides compare as exact strings.
        return deviceId.toLowerCase(java.util.Locale.ROOT);
    }

    /** Base64 as Intune delivers it, falling back to the raw string when that is not what it is. */
    private static String decodeChallengeToken(String challengePassword) {
        try {
            String decoded = new String(Base64.getMimeDecoder().decode(challengePassword),
                    StandardCharsets.UTF_8);
            if (decoded.startsWith(CERT_ENROLL_TOKEN)) {
                return decoded;
            }
        } catch (IllegalArgumentException ignored) {
            // Not base64 at all — fall through to the raw value.
        }
        return challengePassword;
    }

    private static String csrKeyAlgorithm(ScepRequest request) {
        return request.deviceCertificate().getPublicKey().getAlgorithm();
    }

    private static Integer csrKeySize(ScepRequest request) {
        // The SCEP proof-of-possession requires the CSR key to match the signer key, so the device
        // certificate's public key carries the requested key facts without re-parsing the CSR.
        return request.deviceCertificate().getPublicKey() instanceof RSAPublicKey rsa
                ? rsa.getModulus().bitLength() : null;
    }

    private static String bounded(String value) {
        if (value == null) {
            return null;
        }
        return value.length() <= 255 ? value : value.substring(0, 255);
    }

    private void publishIssued(ResolvedEndpoint endpoint, ScepRequest request, IssuedCertificate issued,
                               ScepValidationResult validation, X509Certificate priorCertificate,
                               String providerProfileId, EnrollmentTimeline timeline) {
        try {
            X509Certificate leaf = issued.leaf();
            CertificateMetadata md = CertificateMetadataExtractor.fromLeaf(leaf);
            messageSender.sendScepCertIssued(ScepCertIssuedResponse.builder()
                    .messageVersion(3)
                    .requestId(request.transactionId())
                    .correlationId(request.transactionId())
                    .organizationId(endpoint.organizationId())
                    .connectionProfileRef(endpoint.connectionProfileRef())
                    .endpointId(endpoint.endpointId())
                    // The SCEP request never names its Intune profile. providerProfileId is set only
                    // when exactly one Intune profile points at this endpoint URL.
                    .providerProfileId(providerProfileId)
                    .intuneTransactionId(request.transactionId())
                    .csrFingerprintSha256(request.csrFingerprint())
                    .deviceIdentifier(deviceIdentifier(validation))
                    .enrollmentType(priorCertificate == null ? "INITIAL" : "RENEWAL")
                    .priorCertificateIssuerDn(priorCertificate == null ? null
                            : priorCertificate.getIssuerX500Principal().getName())
                    .priorCertificateSerialNumber(priorCertificate == null ? null
                            : priorCertificate.getSerialNumber().toString(16))
                    .caProvider(issued.caProvider())
                    .caName(issued.caName())
                    .endEntityName(issued.endEntityName())
                    .caProvisionerName(issued.provisionerName())
                    .issuer(leaf.getIssuerX500Principal().getName())
                    .serialNumber(leaf.getSerialNumber().toString(16))
                    .status("ISSUED")
                    .subjectDn(md.subjectDn())
                    .commonName(md.commonName())
                    .subjectAltNames(CertificateSubjectAlternativeNameExtractor.extract(leaf))
                    .fingerprintSha1(digest(leaf, "SHA-1"))
                    .fingerprintSha256(digest(leaf, "SHA-256"))
                    .validFrom(iso(leaf.getNotBefore()))
                    .validTo(iso(leaf.getNotAfter()))
                    .signatureAlgorithm(md.signatureAlgorithm())
                    .signatureAlgorithmOid(md.signatureAlgorithmOid())
                    .publicKeyAlgorithm(md.publicKeyAlgorithm())
                    .keySize(md.keySize())
                    .publicKeyCurve(md.publicKeyCurve())
                    .keyUsage(md.keyUsage())
                    .extendedKeyUsage(md.extendedKeyUsage())
                    .subjectKeyIdentifier(md.subjectKeyIdentifier())
                    .authorityKeyIdentifier(md.authorityKeyIdentifier())
                    .certificatePolicyOids(md.certificatePolicyOids())
                    .certificateAuthority(md.certificateAuthority())
                    .requestedAt(timeline.requestedAt().toString())
                    .validatedAt(timeline.validatedAt().toString())
                    .issuedAt(timeline.issuedAt().toString())
                    .completedAt(timeline.completedAt().toString())
                    .respondedAt(now().toString())
                    .build());
            // Identifier type and assurance only — the value itself is what decides whether the server
            // may auto-link a device, and it never needs to be in a log to answer that.
            //
            // txId is the join key to the server: the published message carries it as its correlation id,
            // so this line and the server-side "SCEP certificate inventory persisted" line pair up.
            log.info("SCEP certificate metadata published: source={} txn={} serial={} "
                            + "enrollmentType={} identifierType={} identifierAssurance={}",
                    endpoint.connectionProfileRef(), request.transactionId(),
                    leaf.getSerialNumber().toString(16),
                    priorCertificate == null ? "INITIAL" : "RENEWAL",
                    validation.hasIdentifier() ? validation.identifier().type() : null,
                    validation.hasIdentifier() ? validation.identifier().assurance() : null);
        } catch (Exception e) {
            // The device already has its certificate; a failed metadata publish must not fail issuance.
            log.error("SCEP cert issued but SCEP_CERT_ISSUED publish failed txn={}: {}",
                    request.transactionId(), e.getMessage());
        }
    }

    private static ScepCertIssuedResponse.DeviceIdentifier deviceIdentifier(ScepValidationResult validation) {
        if (!validation.hasIdentifier()) {
            return null;
        }
        ScepValidationResult.DeviceIdentifier identifier = validation.identifier();
        return ScepCertIssuedResponse.DeviceIdentifier.builder()
                .value(identifier.value())
                .type(identifier.type().name())
                .assurance(identifier.assurance().name())
                .provider(identifier.provider())
                .build();
    }

    private static String iso(Date date) {
        return date.toInstant().atOffset(java.time.ZoneOffset.UTC).toString();
    }

    private OffsetDateTime now() {
        return OffsetDateTime.now(clock);
    }

    private record EnrollmentTimeline(
            OffsetDateTime requestedAt,
            OffsetDateTime validatedAt,
            OffsetDateTime issuedAt,
            OffsetDateTime completedAt) {
    }

    private static String digest(X509Certificate cert, String algorithm) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance(algorithm).digest(cert.getEncoded()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
