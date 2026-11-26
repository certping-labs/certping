// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.model.message.ScepCertIssuedResponse;
import com.certping.agent.model.message.ScepCertResultResponse;
import com.certping.agent.platform.DeviceSourceProfile;
import com.certping.agent.platform.DeviceSourceProfileRegistry;
import com.certping.agent.scep.ca.CaException;
import com.certping.agent.scep.ca.NoopScepCaBackend;
import com.certping.agent.scep.ca.ScepCaBackend;
import com.certping.agent.scep.intune.IntuneScepValidator;
import com.certping.agent.scep.intune.NoopIntuneScepValidator;
import com.certping.agent.scep.intune.ScepValidationResult;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Drives the full SCEP PKIOperation path in-process: a real BouncyCastle SCEP client builds a signed,
 * enveloped PKCSReq, the service parses it, signs at the Noop dev CA, and returns a CertRep the client
 * verifies and decrypts. Exercises controller-independent codec + service end to end.
 */
class ScepPkiOperationTest {

    private static final String ENDPOINT = "intune-primary";
    private static final String DEVICE_GUID = "1a2b3c4d-0000-4000-8000-000000000001";
    private static final String OTHER_DEVICE_GUID = "1a2b3c4d-0000-4000-8000-000000000002";

    private ScepCaBackend caBackend;
    private ScepService service;
    private AgentMessageSender sender;
    private X509Certificate raCert;

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() {
        AgentProperties props = new AgentProperties();
        props.setOrganizationId("42");
        props.getScep().setTxnStateTtl(Duration.ofMinutes(15));

        caBackend = new NoopScepCaBackend();
        raCert = caBackend.getRaCertificate();

        ScepEndpointRegistry registry = registry(props, caBackend);

        sender = Mockito.mock(AgentMessageSender.class);
        service = new ScepService(registry, new PkiMessageCodec(),
                new NoopIntuneScepValidator(), new ScepTransactionStore(props), sender, Clock.systemUTC(), ScepProfileHintResolver.NONE);
    }

    @Test
    void enrolsAndReturnsSuccessCertRepWithIssuedCert() throws Exception {
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=device-1");
        byte[] pkcsReq = buildPkcsReq("txn-0001", device, deviceCert, "CN=device-1", "challenge-abc");

        BinaryResponse response = service.pkiOperation(ENDPOINT, pkcsReq);

        assertThat(response.contentType()).isEqualTo(ScepConstants.CT_PKI_MESSAGE);
        assertThat(pkiStatus(response.body())).isEqualTo(ScepConstants.PKI_STATUS_SUCCESS);

        X509Certificate issued = extractIssuedLeaf(response.body(), device.getPrivate());
        assertThat(issued.getSubjectX500Principal().getName()).contains("device-1");
    }

    @Test
    void retryOfSameTransactionReturnsCachedResponse() throws Exception {
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=device-2");
        byte[] pkcsReq = buildPkcsReq("txn-0002", device, deviceCert, "CN=device-2", "c");

        BinaryResponse first = service.pkiOperation(ENDPOINT, pkcsReq);
        BinaryResponse second = service.pkiOperation(ENDPOINT, pkcsReq);

        assertThat(second.body()).isEqualTo(first.body());
    }

    @Test
    void sameTransactionWithDifferentCsrIsAConflict() throws Exception {
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=device-3");
        service.pkiOperation(ENDPOINT, buildPkcsReq("txn-0003", device, deviceCert, "CN=device-3", "c"));

        KeyPair other = rsa();
        X509Certificate otherCert = selfSigned(other, "CN=device-3b");
        byte[] different = buildPkcsReq("txn-0003", other, otherCert, "CN=device-3b", "c");

        assertThatThrownBy(() -> service.pkiOperation(ENDPOINT, different))
                .isInstanceOf(ScepConflictException.class);
    }

    @Test
    void getCaCapsListsAdvertisedCapabilities() {
        String caps = new String(service.getCaCaps(ENDPOINT).body());
        assertThat(caps).contains("POSTPKIOperation").contains("SHA-256");
    }

    @Test
    void publishesScepCertIssuedWithCertMetadata() throws Exception {
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=device-8");
        service.pkiOperation(ENDPOINT, buildPkcsReq("txn-0008", device, deviceCert, "CN=device-8", "c"));

        // The publish is async (off the request thread), so wait for it.
        ArgumentCaptor<ScepCertIssuedResponse> captor = ArgumentCaptor.forClass(ScepCertIssuedResponse.class);
        Mockito.verify(sender, Mockito.timeout(2000)).sendScepCertIssued(captor.capture());
        ScepCertIssuedResponse msg = captor.getValue();

        assertThat(msg.getOrganizationId()).isEqualTo("42");
        assertThat(msg.getEndpointId()).isEqualTo(ENDPOINT);
        assertThat(msg.getIntuneTransactionId()).isEqualTo("txn-0008");
        assertThat(msg.getStatus()).isEqualTo("ISSUED");
        assertThat(msg.getSerialNumber()).isNotBlank();
        assertThat(msg.getIssuer()).isNotBlank();
        assertThat(msg.getSubjectDn()).contains("device-8");
        assertThat(msg.getFingerprintSha256()).isNotBlank();
        assertThat(msg.getCsrFingerprintSha256()).hasSize(64);
        assertThat(msg.getMessageVersion()).isEqualTo(3);
        assertThat(msg.getConnectionProfileRef()).isEqualTo(ENDPOINT);
        // The route key must never masquerade as a certificate profile reference.
        assertThat(msg.getProfileXref()).isNull();
        assertThat(msg.getProviderProfileId()).isNull();
        assertThat(msg.getEnrollmentType()).isEqualTo("INITIAL");
        assertThat(msg.getPriorCertificateIssuerDn()).isNull();
        assertThat(msg.getPriorCertificateSerialNumber()).isNull();
    }

    @Test
    void profileHintSetsTheCaValidityAndThePublishedIntuneProfileId() throws Exception {
        ScepCaBackend backend = Mockito.spy(caBackend);
        AgentProperties props = properties();
        service = new ScepService(registry(props, backend), new PkiMessageCodec(),
                new NoopIntuneScepValidator(), new ScepTransactionStore(props), sender,
                Clock.systemUTC(), endpoint -> new ScepProfileHintResolver.ScepProfileHint(
                        "intune-profile-1", Duration.ofDays(365)));
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=device-hint");

        service.pkiOperation(ENDPOINT,
                buildPkcsReq("txn-hint", device, deviceCert, "CN=device-hint", "c"));

        Mockito.verify(backend).sign(Mockito.any(), Mockito.eq(Duration.ofDays(365)));
        ArgumentCaptor<ScepCertIssuedResponse> captor =
                ArgumentCaptor.forClass(ScepCertIssuedResponse.class);
        Mockito.verify(sender, Mockito.timeout(2000)).sendScepCertIssued(captor.capture());
        assertThat(captor.getValue().getProviderProfileId()).isEqualTo("intune-profile-1");
        assertThat(captor.getValue().getProfileXref()).isNull();
    }

    @Test
    void publishesDeviceIdEstablishedByChallengeValidation() throws Exception {
        ScepEndpointRegistry registry = registry(properties(), caBackend);
        service = new ScepService(registry, new PkiMessageCodec(),
                new NoopIntuneScepValidator() {
                    @Override
                    public ScepValidationResult validate(ResolvedEndpoint endpoint,
                                                         String transactionId, String csrBase64) {
                        return ScepValidationResult.asserted("windows-scep-e2e",
                                ScepValidationResult.IdentifierType.MANAGED_DEVICE_ID);
                    }
                }, new ScepTransactionStore(properties()), sender, Clock.systemUTC(), ScepProfileHintResolver.NONE);
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=device-bound");

        service.pkiOperation(ENDPOINT,
                buildPkcsReq("txn-device-bound", device, deviceCert, "CN=device-bound", "challenge"));

        ArgumentCaptor<ScepCertIssuedResponse> captor = ArgumentCaptor.forClass(ScepCertIssuedResponse.class);
        Mockito.verify(sender, Mockito.timeout(2000)).sendScepCertIssued(captor.capture());
        ScepCertIssuedResponse.DeviceIdentifier identifier = captor.getValue().getDeviceIdentifier();
        assertThat(identifier).isNotNull();
        assertThat(identifier.getValue()).isEqualTo("windows-scep-e2e");
        assertThat(identifier.getType()).isEqualTo("MANAGED_DEVICE_ID");
        assertThat(identifier.getAssurance()).isEqualTo("ASSERTED");
        assertThat(identifier.getProvider()).isEqualTo("INTUNE");
    }

    /** A challenge token the agent can mine a DeviceId out of, base64 as Intune delivers it. */
    private static String challengeToken(String deviceId) {
        String xml = "<CertEnrollToken><DeviceId>" + deviceId + "</DeviceId></CertEnrollToken>";
        return java.util.Base64.getEncoder()
                .encodeToString(xml.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /** Accepts everything like the NOOP validator, but reports that it really called Microsoft. */
    private static final class RealValidatorStub extends NoopIntuneScepValidator {
        @Override
        public boolean validatesWithMicrosoft() {
            return true;
        }
    }

    @Test
    void deviceIdMatchingTheValidatedSubjectIsPublishedAsMicrosoftValidated() throws Exception {
        // Intune binds the CSR subject to the challenge (proven: altering it yields
        // SubjectNameMismatch). A DeviceId equal to that validated subject is therefore trustworthy.
        ScepEndpointRegistry registry = registry(properties(), caBackend);
        service = new ScepService(registry, new PkiMessageCodec(), new RealValidatorStub(),
                new ScepTransactionStore(properties()), sender, Clock.systemUTC(), ScepProfileHintResolver.NONE);
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=" + DEVICE_GUID);

        service.pkiOperation(ENDPOINT, buildPkcsReq("txn-validated", device, deviceCert,
                "CN=" + DEVICE_GUID, challengeToken(DEVICE_GUID)));

        ArgumentCaptor<ScepCertIssuedResponse> captor =
                ArgumentCaptor.forClass(ScepCertIssuedResponse.class);
        Mockito.verify(sender, Mockito.timeout(2000)).sendScepCertIssued(captor.capture());
        ScepCertIssuedResponse.DeviceIdentifier identifier = captor.getValue().getDeviceIdentifier();
        assertThat(identifier).isNotNull();
        assertThat(identifier.getValue()).isEqualTo(DEVICE_GUID);
        assertThat(identifier.getType()).isEqualTo("MANAGED_DEVICE_ID");
        assertThat(identifier.getAssurance()).isEqualTo("MICROSOFT_VALIDATED");
    }

    @Test
    void deviceIdSeenByTheNoopValidatorStaysAsserted() throws Exception {
        // The NOOP validator accepts everything, so nothing it saw is proven — publishing this as
        // MICROSOFT_VALIDATED would let a local dev run auto-link real devices.
        ScepEndpointRegistry registry = registry(properties(), caBackend);
        service = new ScepService(registry, new PkiMessageCodec(), new NoopIntuneScepValidator(),
                new ScepTransactionStore(properties()), sender, Clock.systemUTC(), ScepProfileHintResolver.NONE);
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=" + DEVICE_GUID);

        service.pkiOperation(ENDPOINT, buildPkcsReq("txn-unproven", device, deviceCert,
                "CN=" + DEVICE_GUID, challengeToken(DEVICE_GUID)));

        ArgumentCaptor<ScepCertIssuedResponse> captor =
                ArgumentCaptor.forClass(ScepCertIssuedResponse.class);
        Mockito.verify(sender, Mockito.timeout(2000)).sendScepCertIssued(captor.capture());
        assertThat(captor.getValue().getDeviceIdentifier().getAssurance()).isEqualTo("ASSERTED");
    }


    @Test
    void aSubjectInAnotherNamespacePublishesTheValidatedSubjectAsUndetermined() throws Exception {
        // Real case: the Intune profile puts the Entra device id in the subject while the token
        // carries the Intune managed-device id. Both name the same machine, so the agent publishes
        // the value Intune actually validated — the subject — and leaves the namespace to
        // the server rather than guessing.
        ScepEndpointRegistry registry = registry(properties(), caBackend);
        service = new ScepService(registry, new PkiMessageCodec(), new RealValidatorStub(),
                new ScepTransactionStore(properties()), sender, Clock.systemUTC(), ScepProfileHintResolver.NONE);
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=" + DEVICE_GUID);

        service.pkiOperation(ENDPOINT, buildPkcsReq("txn-other-namespace", device, deviceCert,
                "CN=" + DEVICE_GUID, challengeToken(OTHER_DEVICE_GUID)));

        ArgumentCaptor<ScepCertIssuedResponse> captor =
                ArgumentCaptor.forClass(ScepCertIssuedResponse.class);
        Mockito.verify(sender, Mockito.timeout(2000)).sendScepCertIssued(captor.capture());
        ScepCertIssuedResponse.DeviceIdentifier identifier = captor.getValue().getDeviceIdentifier();
        assertThat(identifier.getValue()).isEqualTo(DEVICE_GUID);        // the validated subject
        assertThat(identifier.getType()).isEqualTo("UNKNOWN");           // namespace undetermined
        assertThat(identifier.getAssurance()).isEqualTo("MICROSOFT_VALIDATED");
    }

    @Test
    void aNonGuidSubjectFallsBackToTheUnprovenTokenValue() throws Exception {
        // Subject formats like {{SerialNumber}} or {{DeviceName}} are validated but not resolvable
        // to a device namespace, so nothing auto-linkable may be published.
        ScepEndpointRegistry registry = registry(properties(), caBackend);
        service = new ScepService(registry, new PkiMessageCodec(), new RealValidatorStub(),
                new ScepTransactionStore(properties()), sender, Clock.systemUTC(), ScepProfileHintResolver.NONE);
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=MacBook-Pro-of-Sam");

        service.pkiOperation(ENDPOINT, buildPkcsReq("txn-name-subject", device, deviceCert,
                "CN=MacBook-Pro-of-Sam", challengeToken(OTHER_DEVICE_GUID)));

        ArgumentCaptor<ScepCertIssuedResponse> captor =
                ArgumentCaptor.forClass(ScepCertIssuedResponse.class);
        Mockito.verify(sender, Mockito.timeout(2000)).sendScepCertIssued(captor.capture());
        ScepCertIssuedResponse.DeviceIdentifier identifier = captor.getValue().getDeviceIdentifier();
        assertThat(identifier.getValue()).isEqualTo(OTHER_DEVICE_GUID);
        assertThat(identifier.getAssurance()).isEqualTo("ASSERTED");
    }

    @Test
    void tokenCarryingTwoDeviceIdsYieldsNoIdentifierAtAll() throws Exception {
        ScepEndpointRegistry registry = registry(properties(), caBackend);
        service = new ScepService(registry, new PkiMessageCodec(), new RealValidatorStub(),
                new ScepTransactionStore(properties()), sender, Clock.systemUTC(), ScepProfileHintResolver.NONE);
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=" + DEVICE_GUID);
        String ambiguous = java.util.Base64.getEncoder().encodeToString(
                ("<CertEnrollToken><DeviceId>" + DEVICE_GUID + "</DeviceId><DeviceId>"
                        + OTHER_DEVICE_GUID + "</DeviceId></CertEnrollToken>")
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8));

        service.pkiOperation(ENDPOINT, buildPkcsReq("txn-ambiguous", device, deviceCert,
                "CN=" + DEVICE_GUID, ambiguous));

        ArgumentCaptor<ScepCertIssuedResponse> captor =
                ArgumentCaptor.forClass(ScepCertIssuedResponse.class);
        Mockito.verify(sender, Mockito.timeout(2000)).sendScepCertIssued(captor.capture());
        assertThat(captor.getValue().getDeviceIdentifier()).isNull();
    }

    @Test
    void realValidatorReportsThatItContactsMicrosoft() {
        // Losing this override silently disables all device linking in production.
        assertThat(new com.certping.agent.scep.intune.MicrosoftIntuneScepValidator(
                null, null, null, "CertPing/1.0").validatesWithMicrosoft()).isTrue();
        assertThat(new NoopIntuneScepValidator().validatesWithMicrosoft()).isFalse();
    }

    @Test
    void intuneNotificationFailureDoesNotSuppressCmsMetadataPublish() throws Exception {
        ScepEndpointRegistry registry = registry(properties(), caBackend);
        service = new ScepService(registry, new PkiMessageCodec(),
                new NoopIntuneScepValidator() {
                    @Override
                    public void notifySuccess(ResolvedEndpoint endpoint, String transactionId,
                                              String csrBase64, String certThumbprint,
                                              String serialNumber, String certExpiration,
                                              String certificateAuthority,
                                              String certificateAuthorityName, String certificateTemplate) {
                        throw new IllegalStateException("Intune unavailable");
                    }
                }, new ScepTransactionStore(properties()), sender, Clock.systemUTC(), ScepProfileHintResolver.NONE);
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=device-notify-failure");

        BinaryResponse response = service.pkiOperation(ENDPOINT, buildPkcsReq(
                "txn-notify-failure", device, deviceCert, "CN=device-notify-failure", "challenge"));

        assertThat(pkiStatus(response.body())).isEqualTo(ScepConstants.PKI_STATUS_SUCCESS);
        Mockito.verify(sender, Mockito.timeout(2000)).sendScepCertIssued(Mockito.argThat(message ->
                "txn-notify-failure".equals(message.getIntuneTransactionId())));
    }

    @Test
    void certRepEncodingFailureStillPublishesIssuedCertificateMetadata() throws Exception {
        PkiMessageCodec failingCodec = Mockito.spy(new PkiMessageCodec());
        Mockito.doThrow(new IllegalStateException("encoding failed"))
                .when(failingCodec).buildSuccess(
                        Mockito.any(), Mockito.anyList(), Mockito.any(), Mockito.any());
        ScepEndpointRegistry registry = registry(properties(), caBackend);
        service = new ScepService(registry, failingCodec, new NoopIntuneScepValidator(),
                new ScepTransactionStore(properties()), sender, Clock.systemUTC(), ScepProfileHintResolver.NONE);
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=device-encoding-failure");
        byte[] request = buildPkcsReq("txn-encoding-failure", device, deviceCert,
                "CN=device-encoding-failure", "challenge");

        assertThatThrownBy(() -> service.pkiOperation(ENDPOINT, request))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("failed to build SUCCESS CertRep");

        Mockito.verify(sender, Mockito.timeout(2000)).sendScepCertIssued(Mockito.argThat(message ->
                "txn-encoding-failure".equals(message.getIntuneTransactionId())));
    }

    @Test
    void rejectedChallengeNeverCallsCertificateAuthority() throws Exception {
        ScepCaBackend backend = Mockito.spy(caBackend);
        ScepEndpointRegistry registry = registry(properties(), backend);
        service = new ScepService(registry, new PkiMessageCodec(),
                new NoopIntuneScepValidator() {
                    @Override
                    public ScepValidationResult validate(ResolvedEndpoint endpoint,
                                                         String transactionId, String csrBase64) {
                        throw new ChallengeValidationException("challenge rejected");
                    }
                }, new ScepTransactionStore(properties()), sender, Clock.systemUTC(), ScepProfileHintResolver.NONE);
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=device-rejected");

        BinaryResponse response = service.pkiOperation(ENDPOINT,
                buildPkcsReq("txn-rejected", device, deviceCert, "CN=device-rejected", "challenge"));

        assertThat(pkiStatus(response.body())).isEqualTo(ScepConstants.PKI_STATUS_FAILURE);
        assertThat(failInfo(response.body())).isEqualTo(ScepConstants.FAIL_BAD_MESSAGE_CHECK);
        Mockito.verify(backend, Mockito.never()).sign(Mockito.any(), Mockito.any());
        Mockito.verify(sender, Mockito.never()).sendScepCertIssued(Mockito.any());
    }

    @Test
    void invalidCsrProofOfPossessionIsRejectedBeforeCertificateAuthority() throws Exception {
        ScepCaBackend backend = Mockito.spy(caBackend);
        ScepEndpointRegistry registry = registry(properties(), backend);
        service = new ScepService(registry, new PkiMessageCodec(), new NoopIntuneScepValidator(),
                new ScepTransactionStore(properties()), sender, Clock.systemUTC(), ScepProfileHintResolver.NONE);
        KeyPair device = rsa();
        KeyPair unrelated = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=device-invalid-csr-signature");

        byte[] request = buildMessage("txn-invalid-csr-signature", device, deviceCert,
                "CN=device-invalid-csr-signature", "challenge", ScepConstants.MSG_PKCS_REQ,
                unrelated.getPrivate());

        assertThatThrownBy(() -> service.pkiOperation(ENDPOINT, request))
                .isInstanceOf(BadPkiMessageException.class)
                .hasCauseInstanceOf(SecurityException.class);
        Mockito.verify(backend, Mockito.never()).sign(Mockito.any(), Mockito.any());
    }

    @Test
    void unsupportedClientEncryptionKeyFailsBeforeCertificateAuthority() throws Exception {
        ScepCaBackend backend = Mockito.spy(caBackend);
        ScepEndpointRegistry registry = registry(properties(), backend);
        service = new ScepService(registry, new PkiMessageCodec(), new NoopIntuneScepValidator(),
                new ScepTransactionStore(properties()), sender, Clock.systemUTC(), ScepProfileHintResolver.NONE);
        KeyPair device = ec();
        X509Certificate deviceCert = selfSigned(device, "CN=device-ec");

        BinaryResponse response = service.pkiOperation(ENDPOINT,
                buildPkcsReq("txn-ec", device, deviceCert, "CN=device-ec", "challenge"));

        assertThat(pkiStatus(response.body())).isEqualTo(ScepConstants.PKI_STATUS_FAILURE);
        assertThat(failInfo(response.body())).isEqualTo(ScepConstants.FAIL_BAD_ALG);
        Mockito.verify(backend, Mockito.never()).sign(Mockito.any(), Mockito.any());
        Mockito.verify(sender, Mockito.never()).sendScepCertIssued(Mockito.any());
    }

    @Test
    void nullValidationResultFailsClosedBeforeCertificateAuthority() throws Exception {
        ScepCaBackend backend = Mockito.spy(caBackend);
        ScepEndpointRegistry registry = registry(properties(), backend);
        service = new ScepService(registry, new PkiMessageCodec(),
                new NoopIntuneScepValidator() {
                    @Override
                    public ScepValidationResult validate(ResolvedEndpoint endpoint,
                                                         String transactionId, String csrBase64) {
                        return null;
                    }
                }, new ScepTransactionStore(properties()), sender, Clock.systemUTC(), ScepProfileHintResolver.NONE);
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=device-null-validation");

        BinaryResponse response = service.pkiOperation(ENDPOINT, buildPkcsReq(
                "txn-null-validation", device, deviceCert, "CN=device-null-validation", "challenge"));

        assertThat(pkiStatus(response.body())).isEqualTo(ScepConstants.PKI_STATUS_FAILURE);
        Mockito.verify(backend, Mockito.never()).sign(Mockito.any(), Mockito.any());
        Mockito.verify(sender, Mockito.never()).sendScepCertIssued(Mockito.any());
    }

    @Test
    void hangingPublishDoesNotBlockTheCertRep() throws Exception {
        // A send to the server that blocks forever must not hold the device's CertRep.
        Mockito.doAnswer(inv -> {
            Thread.sleep(10_000);
            return null;
        }).when(sender).sendScepCertIssued(Mockito.any());

        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=device-9");
        byte[] req = buildPkcsReq("txn-0009", device, deviceCert, "CN=device-9", "c");

        long startNs = System.nanoTime();
        BinaryResponse response = service.pkiOperation(ENDPOINT, req);
        long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;

        assertThat(pkiStatus(response.body())).isEqualTo(ScepConstants.PKI_STATUS_SUCCESS);
        assertThat(elapsedMs).isLessThan(5_000);   // returned without waiting on the 10s publish
    }

    @Test
    void getCaCertReturnsRaAndCaBundle() {
        BinaryResponse response = service.getCaCert(ENDPOINT);
        assertThat(response.contentType()).isEqualTo(ScepConstants.CT_CA_RA_CERT);
        assertThat(response.body()).isNotEmpty();
    }

    @Test
    void caFailureIsReturnedAsFailureCertRep() throws Exception {
        ScepService failing = serviceWith(new FailingCaBackend(caBackend));
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=device-4");
        byte[] req = buildPkcsReq("txn-0004", device, deviceCert, "CN=device-4", "c");

        BinaryResponse response = failing.pkiOperation(ENDPOINT, req);

        assertThat(pkiStatus(response.body())).isEqualTo(ScepConstants.PKI_STATUS_FAILURE);
        assertThat(failInfo(response.body())).isEqualTo(ScepConstants.FAIL_BAD_REQUEST);
    }

    @Test
    void caFailureAfterValidationNotifiesIntune() throws Exception {
        RecordingValidator validator = new RecordingValidator();
        ScepService failing = serviceWith(new FailingCaBackend(caBackend),
                Mockito.mock(AgentMessageSender.class), validator);
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=device-4b");
        byte[] req = buildPkcsReq("txn-0004b", device, deviceCert, "CN=device-4b", "c");

        BinaryResponse response = failing.pkiOperation(ENDPOINT, req);

        assertThat(failInfo(response.body())).isEqualTo(ScepConstants.FAIL_BAD_REQUEST);
        assertThat(validator.failureNotifications()).isEqualTo(1);
    }

    @Test
    void enrollmentPublishesRequestedThenIssued() throws Exception {
        AgentMessageSender sender = Mockito.mock(AgentMessageSender.class);
        ScepService svc = serviceWith(caBackend, sender, new NoopIntuneScepValidator());
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=req-1");

        svc.pkiOperation(ENDPOINT, buildPkcsReq("txn-req-1", device, deviceCert, "CN=req-1", "c"));

        Mockito.verify(sender, Mockito.timeout(2000)).sendScepCertRequested(Mockito.any());
        Mockito.verify(sender, Mockito.timeout(2000)).sendScepCertIssued(Mockito.any());
        Mockito.verify(sender, Mockito.never()).sendScepCertResult(Mockito.any());
    }

    @Test
    void challengeRejectionPublishesRejectedResult() throws Exception {
        AgentMessageSender sender = Mockito.mock(AgentMessageSender.class);
        RecordingValidator validator = new RecordingValidator(new ChallengeValidationException("bad"));
        ScepService svc = serviceWith(caBackend, sender, validator);
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=req-2");

        svc.pkiOperation(ENDPOINT, buildPkcsReq("txn-req-2", device, deviceCert, "CN=req-2", "c"));

        Mockito.verify(sender, Mockito.timeout(2000)).sendScepCertRequested(Mockito.any());
        ArgumentCaptor<ScepCertResultResponse> captor = ArgumentCaptor.forClass(ScepCertResultResponse.class);
        Mockito.verify(sender, Mockito.timeout(2000)).sendScepCertResult(captor.capture());
        assertThat(captor.getValue().getStatus()).isEqualTo("REJECTED");
        assertThat(captor.getValue().getStage()).isEqualTo("INTUNE_VALIDATION");
        Mockito.verify(sender, Mockito.never()).sendScepCertIssued(Mockito.any());
    }

    @Test
    void caFailurePublishesFailedResult() throws Exception {
        AgentMessageSender sender = Mockito.mock(AgentMessageSender.class);
        ScepService svc = serviceWith(new FailingCaBackend(caBackend), sender, new NoopIntuneScepValidator());
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=req-3");

        svc.pkiOperation(ENDPOINT, buildPkcsReq("txn-req-3", device, deviceCert, "CN=req-3", "c"));

        ArgumentCaptor<ScepCertResultResponse> captor = ArgumentCaptor.forClass(ScepCertResultResponse.class);
        Mockito.verify(sender, Mockito.timeout(2000)).sendScepCertResult(captor.capture());
        assertThat(captor.getValue().getStatus()).isEqualTo("FAILED");
        assertThat(captor.getValue().getStage()).isEqualTo("CA_SIGNING");
        Mockito.verify(sender, Mockito.never()).sendScepCertIssued(Mockito.any());
    }

    @Test
    void challengeRejectionReturnsFailureAndDoesNotNotifyIntune() throws Exception {
        RecordingValidator validator =
                new RecordingValidator(new ChallengeValidationException("bad challenge"));
        ScepCaBackend backend = Mockito.spy(caBackend);
        ScepService service = serviceWith(backend, Mockito.mock(AgentMessageSender.class), validator);
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=device-4c");
        byte[] req = buildPkcsReq("txn-0004c", device, deviceCert, "CN=device-4c", "c");

        BinaryResponse response = service.pkiOperation(ENDPOINT, req);

        assertThat(failInfo(response.body())).isEqualTo(ScepConstants.FAIL_BAD_MESSAGE_CHECK);
        assertThat(validator.failureNotifications()).isZero();
        Mockito.verify(backend, Mockito.never()).sign(Mockito.any(), Mockito.any());
    }

    @Test
    void intuneOutageDuringValidationSurfacesAsUnavailable() throws Exception {
        RecordingValidator validator =
                new RecordingValidator(new IntuneUnavailableException("service down"));
        ScepCaBackend backend = Mockito.spy(caBackend);
        ScepService service = serviceWith(backend, Mockito.mock(AgentMessageSender.class), validator);
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=device-4d");
        byte[] req = buildPkcsReq("txn-0004d", device, deviceCert, "CN=device-4d", "c");

        assertThatThrownBy(() -> service.pkiOperation(ENDPOINT, req))
                .isInstanceOf(IntuneUnavailableException.class);
        assertThat(validator.failureNotifications()).isZero();
        Mockito.verify(backend, Mockito.never()).sign(Mockito.any(), Mockito.any());
    }

    @Test
    void successfulRenewalDoesNotNotifyIntune() throws Exception {
        RecordingValidator validator = new RecordingValidator();
        ScepService service = serviceWith(caBackend, Mockito.mock(AgentMessageSender.class), validator);
        KeyPair keys = rsa();
        X509Certificate bootstrap = selfSigned(keys, "CN=renew-notify");
        BinaryResponse initial = service.pkiOperation(ENDPOINT,
                buildPkcsReq("txn-renew-notify-initial", keys, bootstrap, "CN=renew-notify", "challenge"));
        X509Certificate current = extractIssuedLeaf(initial.body(), keys.getPrivate());
        assertThat(validator.successNotifications()).isEqualTo(1);   // the initial PKCSReq notifies

        BinaryResponse renewal = service.pkiOperation(ENDPOINT, buildMessage(
                "txn-renew-notify", keys, current, rsa(), "CN=renew-notify", "",
                ScepConstants.MSG_RENEWAL_REQ));

        assertThat(pkiStatus(renewal.body())).isEqualTo(ScepConstants.PKI_STATUS_SUCCESS);
        assertThat(validator.successNotifications()).isEqualTo(1);   // the renewal must not notify Intune
    }

    @Test
    void unsupportedMessageTypeIsFailureBadRequest() throws Exception {
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=device-5");
        byte[] req = buildMessage("txn-0005", device, deviceCert, "CN=device-5", "c", 99);

        BinaryResponse response = service.pkiOperation(ENDPOINT, req);

        assertThat(pkiStatus(response.body())).isEqualTo(ScepConstants.PKI_STATUS_FAILURE);
        assertThat(failInfo(response.body())).isEqualTo(ScepConstants.FAIL_BAD_REQUEST);
    }

    @Test
    void renewalSignedByForeignCertIsBadMessageCheck() throws Exception {
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=device-6");
        byte[] req = buildMessage("txn-0006", device, deviceCert, "CN=device-6", "c",
                ScepConstants.MSG_RENEWAL_REQ);

        BinaryResponse response = service.pkiOperation(ENDPOINT, req);

        assertThat(pkiStatus(response.body())).isEqualTo(ScepConstants.PKI_STATUS_FAILURE);
        assertThat(failInfo(response.body())).isEqualTo(ScepConstants.FAIL_BAD_MESSAGE_CHECK);
    }

    @Test
    void renewalWithForgedIssuerTextIsRejectedBeforeCertificateAuthority() throws Exception {
        ScepCaBackend backend = Mockito.spy(caBackend);
        ScepService renewalService = serviceWith(backend);
        KeyPair attacker = rsa();
        String caSubject = caBackend.getCaChain().getFirst().getSubjectX500Principal().getName();
        X509Certificate forgedCertificate = certificate(attacker.getPublic(), "CN=forged-device",
                caSubject, attacker.getPrivate(), false);

        BinaryResponse response = renewalService.pkiOperation(ENDPOINT, buildMessage(
                "txn-forged-renewal", attacker, forgedCertificate, "CN=forged-device", "c",
                ScepConstants.MSG_RENEWAL_REQ));

        assertThat(pkiStatus(response.body())).isEqualTo(ScepConstants.PKI_STATUS_FAILURE);
        assertThat(failInfo(response.body())).isEqualTo(ScepConstants.FAIL_BAD_MESSAGE_CHECK);
        Mockito.verify(backend, Mockito.never()).sign(Mockito.any(), Mockito.any());
    }

    @Test
    void renewalWithoutConfiguredIssuerCertificateIsRejectedBeforeCertificateAuthority()
            throws Exception {
        ScepCaBackend backend = Mockito.spy(caBackend);
        Mockito.when(backend.getCaChain()).thenReturn(List.of());
        ScepService renewalService = serviceWith(backend);
        KeyPair device = rsa();
        X509Certificate deviceCertificate = selfSigned(device, "CN=no-renewal-ca");

        BinaryResponse response = renewalService.pkiOperation(ENDPOINT, buildMessage(
                "txn-no-renewal-ca", device, deviceCertificate, "CN=no-renewal-ca", "c",
                ScepConstants.MSG_RENEWAL_REQ));

        assertThat(pkiStatus(response.body())).isEqualTo(ScepConstants.PKI_STATUS_FAILURE);
        Mockito.verify(backend, Mockito.never()).sign(Mockito.any(), Mockito.any());
    }

    @Test
    void renewalWithChangedSubjectIsRejectedBeforeCertificateAuthority() throws Exception {
        ScepCaBackend backend = Mockito.spy(caBackend);
        ScepService renewalService = serviceWith(backend);
        KeyPair currentKeys = rsa();
        X509Certificate bootstrapCertificate = selfSigned(currentKeys, "CN=original-device");
        BinaryResponse initialResponse = renewalService.pkiOperation(ENDPOINT, buildPkcsReq(
                "txn-original-device", currentKeys, bootstrapCertificate,
                "CN=original-device", "challenge"));
        X509Certificate currentCertificate = extractIssuedLeaf(
                initialResponse.body(), currentKeys.getPrivate());

        BinaryResponse renewalResponse = renewalService.pkiOperation(ENDPOINT, buildMessage(
                "txn-changed-subject", currentKeys, currentCertificate, rsa(),
                "CN=other-device", "", ScepConstants.MSG_RENEWAL_REQ));

        assertThat(pkiStatus(renewalResponse.body())).isEqualTo(ScepConstants.PKI_STATUS_FAILURE);
        assertThat(failInfo(renewalResponse.body())).isEqualTo(ScepConstants.FAIL_BAD_MESSAGE_CHECK);
        Mockito.verify(backend, Mockito.times(1)).sign(Mockito.any(), Mockito.any());
    }

    @Test
    void verifiedRsaToEcRenewalPublishesExactPriorCertificateIdentity() throws Exception {
        ScepCaBackend backend = Mockito.spy(caBackend);
        service = serviceWith(backend, sender);
        KeyPair currentKeys = rsa();
        X509Certificate bootstrapCertificate = selfSigned(currentKeys, "CN=renewed-device");
        BinaryResponse initialResponse = service.pkiOperation(ENDPOINT, buildPkcsReq(
                "txn-renewed-device-initial", currentKeys, bootstrapCertificate,
                "CN=renewed-device", "challenge"));
        X509Certificate currentCertificate = extractIssuedLeaf(
                initialResponse.body(), currentKeys.getPrivate());
        Mockito.verify(sender, Mockito.timeout(2000)).sendScepCertIssued(Mockito.any());
        Mockito.clearInvocations(sender);

        KeyPair renewedKeys = ec();
        BinaryResponse renewalResponse = service.pkiOperation(ENDPOINT, buildMessage(
                "txn-renewed-device", currentKeys, currentCertificate, renewedKeys,
                "CN=renewed-device", "", ScepConstants.MSG_RENEWAL_REQ));

        assertThat(pkiStatus(renewalResponse.body())).isEqualTo(ScepConstants.PKI_STATUS_SUCCESS);
        X509Certificate renewedCertificate = extractIssuedLeaf(
                renewalResponse.body(), currentKeys.getPrivate());
        assertThat(renewedCertificate.getPublicKey().getAlgorithm()).isEqualTo("EC");
        ArgumentCaptor<ScepCertIssuedResponse> captor =
                ArgumentCaptor.forClass(ScepCertIssuedResponse.class);
        Mockito.verify(sender, Mockito.timeout(2000)).sendScepCertIssued(captor.capture());
        assertThat(captor.getValue()).satisfies(message -> {
            assertThat(message.getEnrollmentType()).isEqualTo("RENEWAL");
            assertThat(message.getPriorCertificateIssuerDn())
                    .isEqualTo(currentCertificate.getIssuerX500Principal().getName());
            assertThat(message.getPriorCertificateSerialNumber())
                    .isEqualTo(currentCertificate.getSerialNumber().toString(16));
            assertThat(message.getPublicKeyCurve()).isEqualTo("1.2.840.10045.3.1.7");
        });
        Mockito.verify(backend, Mockito.times(2)).sign(Mockito.any(), Mockito.any());
    }

    @Test
    void certPollWithNoPendingIsFailure() throws Exception {
        KeyPair device = rsa();
        X509Certificate deviceCert = selfSigned(device, "CN=device-7");
        byte[] req = buildMessage("txn-0007", device, deviceCert, "CN=device-7", "c",
                ScepConstants.MSG_CERT_POLL);

        BinaryResponse response = service.pkiOperation(ENDPOINT, req);

        assertThat(pkiStatus(response.body())).isEqualTo(ScepConstants.PKI_STATUS_FAILURE);
    }

    @Test
    void unknownEndpointThrows() {
        assertThatThrownBy(() -> service.getCaCaps("does-not-exist"))
                .isInstanceOf(UnknownEndpointException.class);
    }

    private ScepService serviceWith(com.certping.agent.scep.ca.ScepCaBackend backend) {
        return serviceWith(backend, Mockito.mock(AgentMessageSender.class));
    }

    private ScepService serviceWith(com.certping.agent.scep.ca.ScepCaBackend backend,
                                    AgentMessageSender messageSender) {
        return serviceWith(backend, messageSender, new NoopIntuneScepValidator());
    }

    private ScepService serviceWith(com.certping.agent.scep.ca.ScepCaBackend backend,
                                    AgentMessageSender messageSender, IntuneScepValidator validator) {
        AgentProperties props = properties();
        ScepEndpointRegistry registry = registry(props, backend);
        return new ScepService(registry, new PkiMessageCodec(), validator,
                new ScepTransactionStore(props), messageSender, Clock.systemUTC(), ScepProfileHintResolver.NONE);
    }

    /** A registry bootstrapped from one Intune device source named {@link #ENDPOINT}. */
    private static ScepEndpointRegistry registry(AgentProperties props, ScepCaBackend backend) {
        DeviceSourceProfileRegistry sources = Mockito.mock(DeviceSourceProfileRegistry.class);
        Mockito.when(sources.all()).thenReturn(List.of(new DeviceSourceProfile(
                ENDPOINT, DevicePlatformType.INTUNE, "ENDPOINT_MANAGEMENT",
                "Test Intune", null, java.util.Map.of())));
        ScepEndpointRegistry registry = new ScepEndpointRegistry(props, backend, sources);
        registry.bootstrap();
        return registry;
    }

    /** Records whether Intune was told about a failure, and can fail validation on demand. */
    private static final class RecordingValidator implements IntuneScepValidator {
        private final RuntimeException validationError;
        private final java.util.concurrent.atomic.AtomicInteger failureNotifications =
                new java.util.concurrent.atomic.AtomicInteger();
        private final java.util.concurrent.atomic.AtomicInteger successNotifications =
                new java.util.concurrent.atomic.AtomicInteger();

        RecordingValidator() {
            this(null);
        }

        RecordingValidator(RuntimeException validationError) {
            this.validationError = validationError;
        }

        @Override
        public ScepValidationResult validate(ResolvedEndpoint endpoint, String transactionId, String csrBase64) {
            if (validationError != null) {
                throw validationError;
            }
            return ScepValidationResult.absent();
        }

        @Override
        public void notifySuccess(ResolvedEndpoint endpoint, String transactionId, String csrBase64,
                                  String thumbprint, String serial, String expiryIso, String issuer,
                                  String caConfig, String certAuthority) {
            successNotifications.incrementAndGet();
        }

        @Override
        public void notifyFailure(ResolvedEndpoint endpoint, String transactionId, String csrBase64,
                                  long hResult, String description) {
            failureNotifications.incrementAndGet();
        }

        int failureNotifications() {
            return failureNotifications.get();
        }

        int successNotifications() {
            return successNotifications.get();
        }
    }

    private static AgentProperties properties() {
        AgentProperties props = new AgentProperties();
        props.setOrganizationId("42");
        return props;
    }

    /** Delegates the RA identity to a real backend but always refuses to sign. */
    private static final class FailingCaBackend implements com.certping.agent.scep.ca.ScepCaBackend {
        private final ScepCaBackend delegate;

        FailingCaBackend(ScepCaBackend delegate) {
            this.delegate = delegate;
        }

        @Override
        public X509Certificate getRaCertificate() {
            return delegate.getRaCertificate();
        }

        @Override
        public PrivateKey getRaPrivateKey() {
            return delegate.getRaPrivateKey();
        }

        @Override
        public java.util.List<X509Certificate> getCaChain() {
            return delegate.getCaChain();
        }

        @Override
        public void assertRenewalAllowed(X509Certificate priorCertificate) throws CaException {
            delegate.assertRenewalAllowed(priorCertificate);
        }

        @Override
        public com.certping.agent.scep.ca.IssuedCertificate sign(PKCS10CertificationRequest csr,
                java.time.Duration validity)
                throws CaException {
            throw new CaException("CA unavailable");
        }
    }

    private static int failInfo(byte[] certRepDer) throws Exception {
        CMSSignedData signed = new CMSSignedData(certRepDer);
        SignerInformation signer = signed.getSignerInfos().getSigners().iterator().next();
        return Integer.parseInt(ASN1PrintableString.getInstance(
                signer.getSignedAttributes().get(ScepConstants.FAIL_INFO)
                        .getAttrValues().getObjectAt(0)).getString());
    }

    // ---- SCEP client helpers --------------------------------------------------------------------

    private byte[] buildPkcsReq(String txId, KeyPair device, X509Certificate deviceCert,
                                String subject, String challenge) throws Exception {
        return buildMessage(txId, device, deviceCert, subject, challenge, ScepConstants.MSG_PKCS_REQ);
    }

    private byte[] buildMessage(String txId, KeyPair device, X509Certificate deviceCert,
                                String subject, String challenge, int messageType) throws Exception {
        return buildMessage(txId, device, deviceCert, subject, challenge, messageType, device.getPrivate());
    }

    private byte[] buildMessage(String txId, KeyPair device, X509Certificate deviceCert,
                                String subject, String challenge, int messageType,
                                PrivateKey csrSigningKey) throws Exception {
        return buildMessage(txId, device, deviceCert, device.getPublic(), subject, challenge,
                messageType, csrSigningKey);
    }

    private byte[] buildMessage(String txId, KeyPair device, X509Certificate deviceCert,
                                KeyPair csrKeys, String subject, String challenge,
                                int messageType) throws Exception {
        return buildMessage(txId, device, deviceCert, csrKeys.getPublic(), subject, challenge,
                messageType, csrKeys.getPrivate());
    }

    private byte[] buildMessage(String txId, KeyPair device, X509Certificate deviceCert,
                                PublicKey csrPublicKey, String subject, String challenge,
                                int messageType, PrivateKey csrSigningKey) throws Exception {
        String csrSignatureAlgorithm = signatureAlgorithm(csrSigningKey);
        PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(
                new X500Name(subject), csrPublicKey)
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, new DERPrintableString(challenge))
                .build(new JcaContentSignerBuilder(csrSignatureAlgorithm).setProvider("BC").build(csrSigningKey));

        CMSEnvelopedDataGenerator envGen = new CMSEnvelopedDataGenerator();
        envGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(raCert).setProvider("BC"));
        CMSEnvelopedData enveloped = envGen.generate(
                new CMSProcessableByteArray(csr.getEncoded()),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider("BC").build());

        ASN1EncodableVector attrs = new ASN1EncodableVector();
        attrs.add(attr(ScepConstants.TRANSACTION_ID, new DERPrintableString(txId)));
        attrs.add(attr(ScepConstants.MESSAGE_TYPE, new DERPrintableString(String.valueOf(messageType))));
        attrs.add(attr(ScepConstants.SENDER_NONCE, new DEROctetString(new byte[16])));

        CMSSignedDataGenerator signGen = new CMSSignedDataGenerator();
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm(device.getPrivate()))
                .setProvider("BC").build(device.getPrivate());
        signGen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(attrs)))
                .build(signer, deviceCert));
        signGen.addCertificate(new JcaX509CertificateHolder(deviceCert));
        return signGen.generate(new CMSProcessableByteArray(enveloped.getEncoded()), true).getEncoded();
    }

    private static int pkiStatus(byte[] certRepDer) throws Exception {
        CMSSignedData signed = new CMSSignedData(certRepDer);
        SignerInformation signer = signed.getSignerInfos().getSigners().iterator().next();
        return Integer.parseInt(ASN1PrintableString.getInstance(
                signer.getSignedAttributes().get(ScepConstants.PKI_STATUS)
                        .getAttrValues().getObjectAt(0)).getString());
    }

    private static X509Certificate extractIssuedLeaf(byte[] certRepDer, PrivateKey deviceKey) throws Exception {
        CMSSignedData signed = new CMSSignedData(certRepDer);
        byte[] envelopedBytes = (byte[]) signed.getSignedContent().getContent();
        CMSEnvelopedData env = new CMSEnvelopedData(envelopedBytes);
        RecipientInformation rid = env.getRecipientInfos().getRecipients().iterator().next();
        byte[] certsOnly = rid.getContent(new JceKeyTransEnvelopedRecipient(deviceKey).setProvider("BC"));

        CMSSignedData degenerate = new CMSSignedData(certsOnly);
        Collection<X509CertificateHolder> certs = degenerate.getCertificates().getMatches(null);
        JcaX509CertificateConverter conv = new JcaX509CertificateConverter().setProvider("BC");
        for (X509CertificateHolder holder : certs) {
            X509Certificate cert = conv.getCertificate(holder);
            if (cert.getBasicConstraints() < 0) { // the leaf, not the CA
                return cert;
            }
        }
        throw new IllegalStateException("no leaf certificate in CertRep");
    }

    private static Attribute attr(ASN1ObjectIdentifier oid, org.bouncycastle.asn1.ASN1Encodable value) {
        return new Attribute(oid, new DERSet(value));
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    private static KeyPair ec() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        return generator.generateKeyPair();
    }

    private static X509Certificate selfSigned(KeyPair keys, String dn) throws Exception {
        return certificate(keys.getPublic(), dn, dn, keys.getPrivate(), false);
    }

    private static X509Certificate certificate(PublicKey publicKey, String subjectDn,
                                               String issuerDn, PrivateKey issuerKey,
                                               boolean isCa) throws Exception {
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name(issuerDn), BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minus(Duration.ofMinutes(5))),
                Date.from(now.plus(Duration.ofDays(1))),
                new X500Name(subjectDn), publicKey);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        ContentSigner cs = new JcaContentSignerBuilder(signatureAlgorithm(issuerKey))
                .setProvider("BC").build(issuerKey);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(cs));
    }

    private static String signatureAlgorithm(PrivateKey key) {
        return "EC".equalsIgnoreCase(key.getAlgorithm()) ? "SHA256withECDSA" : "SHA256withRSA";
    }
}
