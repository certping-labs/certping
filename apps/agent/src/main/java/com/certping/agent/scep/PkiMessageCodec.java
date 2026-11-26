// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
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
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Parses inbound SCEP pkiMessages and builds signed {@code CertRep} replies. All BouncyCastle; the
 * "BC" JCA provider must be registered (done in {@code ScepConfiguration}).
 *
 * <p>MTI crypto per RFC 8894 §2.9: SHA-256 signing digest, AES-128-CBC enveloping.
 */
public class PkiMessageCodec {

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Verify the outer SignedData, read the SCEP signed attributes, decrypt the inner EnvelopedData
     * with the RA key, and extract the CSR, challenge password, and device signer certificate.
     */
    public ScepRequest parse(byte[] der, PrivateKey raPrivateKey) throws Exception {
        CMSSignedData signed = new CMSSignedData(der);
        SignerInformation signer = signed.getSignerInfos().getSigners().iterator().next();
        X509Certificate deviceCert = extractSignerCert(signed, signer);

        if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(deviceCert))) {
            throw new SecurityException("SCEP outer signature verification failed");
        }

        AttributeTable attrs = signer.getSignedAttributes();
        String txId = printable(attrs, ScepConstants.TRANSACTION_ID);
        int msgType = Integer.parseInt(printable(attrs, ScepConstants.MESSAGE_TYPE));
        byte[] nonce = octet(attrs, ScepConstants.SENDER_NONCE);

        byte[] envelopedBytes = (byte[]) signed.getSignedContent().getContent();
        CMSEnvelopedData env = new CMSEnvelopedData(envelopedBytes);
        RecipientInformation rid = env.getRecipientInfos().getRecipients().iterator().next();
        byte[] csrDer = rid.getContent(new JceKeyTransEnvelopedRecipient(raPrivateKey).setProvider("BC"));

        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrDer);
        if (!csr.isSignatureValid(new JcaContentVerifierProviderBuilder()
                .setProvider("BC")
                .build(csr.getSubjectPublicKeyInfo()))) {
            throw new SecurityException("PKCS #10 proof-of-possession signature verification failed");
        }
        String challenge = extractChallengePassword(csr);
        return new ScepRequest(msgType, txId, nonce, csr, csrDer, deviceCert, challenge);
    }

    /** SUCCESS: certs-only PKCS#7 of the issued chain, enveloped to the device key, signed by the RA. */
    public byte[] buildSuccess(ScepRequest req, List<X509Certificate> chain,
                               X509Certificate raCert, PrivateKey raKey) throws Exception {
        byte[] certsOnly = certsOnlyPkcs7(chain);
        CMSEnvelopedDataGenerator env = new CMSEnvelopedDataGenerator();
        env.addRecipientInfoGenerator(
                new JceKeyTransRecipientInfoGenerator(req.deviceCertificate()).setProvider("BC"));
        CMSEnvelopedData enveloped = env.generate(
                new CMSProcessableByteArray(certsOnly),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider("BC").build());
        return signCertRep(req, enveloped.getEncoded(), ScepConstants.PKI_STATUS_SUCCESS, null, raCert, raKey);
    }

    /** FAILURE: no enveloped content, pkiStatus=FAILURE + failInfo, signed by the RA. */
    public byte[] buildFailure(ScepRequest req, int failInfo,
                               X509Certificate raCert, PrivateKey raKey) throws Exception {
        return signCertRep(req, new byte[0], ScepConstants.PKI_STATUS_FAILURE, failInfo, raCert, raKey);
    }

    /** PENDING: no content, pkiStatus=PENDING (manual-approval path). */
    public byte[] buildPending(ScepRequest req, X509Certificate raCert, PrivateKey raKey) throws Exception {
        return signCertRep(req, new byte[0], ScepConstants.PKI_STATUS_PENDING, null, raCert, raKey);
    }

    /** Degenerate certs-only PKCS#7 — used by GetCACert (CA and RA) and inside buildSuccess. */
    public byte[] certsOnlyPkcs7(List<X509Certificate> certs) throws Exception {
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        List<X509CertificateHolder> holders = new ArrayList<>();
        for (X509Certificate c : certs) {
            holders.add(new JcaX509CertificateHolder(c));
        }
        gen.addCertificates(new CollectionStore<>(holders));
        return gen.generate(new CMSAbsentContent()).getEncoded();
    }

    // ---- internals ------------------------------------------------------------------------------

    private byte[] signCertRep(ScepRequest req, byte[] content, int pkiStatus, Integer failInfo,
                               X509Certificate raCert, PrivateKey raKey) throws Exception {
        ASN1EncodableVector a = new ASN1EncodableVector();
        a.add(attr(ScepConstants.TRANSACTION_ID, new DERPrintableString(req.transactionId())));
        a.add(attr(ScepConstants.MESSAGE_TYPE, new DERPrintableString(String.valueOf(ScepConstants.MSG_CERT_REP))));
        a.add(attr(ScepConstants.PKI_STATUS, new DERPrintableString(String.valueOf(pkiStatus))));
        a.add(attr(ScepConstants.SENDER_NONCE, new DEROctetString(random16())));
        a.add(attr(ScepConstants.RECIPIENT_NONCE, new DEROctetString(req.senderNonce())));
        if (failInfo != null) {
            a.add(attr(ScepConstants.FAIL_INFO, new DERPrintableString(String.valueOf(failInfo))));
        }

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner cs = new JcaContentSignerBuilder(sigAlg(raKey)).setProvider("BC").build(raKey);
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(a)))
                .build(cs, raCert));
        gen.addCertificate(new JcaX509CertificateHolder(raCert));
        return gen.generate(new CMSProcessableByteArray(content), true).getEncoded();
    }

    private static Attribute attr(ASN1ObjectIdentifier oid, ASN1Encodable value) {
        return new Attribute(oid, new DERSet(value));
    }

    private static ASN1Encodable value(AttributeTable attrs, ASN1ObjectIdentifier oid) {
        Attribute at = attrs.get(oid);
        if (at == null) {
            throw new IllegalArgumentException("missing SCEP attribute " + oid);
        }
        return at.getAttrValues().getObjectAt(0);
    }

    private static String printable(AttributeTable attrs, ASN1ObjectIdentifier oid) {
        return ASN1PrintableString.getInstance(value(attrs, oid)).getString();
    }

    private static byte[] octet(AttributeTable attrs, ASN1ObjectIdentifier oid) {
        return ASN1OctetString.getInstance(value(attrs, oid)).getOctets();
    }

    private static X509Certificate extractSignerCert(CMSSignedData signed, SignerInformation signer) throws Exception {
        Store<X509CertificateHolder> store = signed.getCertificates();
        Collection<X509CertificateHolder> match = store.getMatches(signer.getSID());
        if (match.isEmpty()) {
            throw new IllegalArgumentException("pkiMessage carries no signer certificate");
        }
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(match.iterator().next());
    }

    private static String extractChallengePassword(PKCS10CertificationRequest csr) {
        org.bouncycastle.asn1.pkcs.Attribute[] c =
                csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
        if (c.length == 0) {
            return null;
        }
        return ((ASN1String) c[0].getAttrValues().getObjectAt(0)).getString();
    }

    private static String sigAlg(PrivateKey key) {
        return "EC".equals(key.getAlgorithm()) ? "SHA256withECDSA" : "SHA256withRSA";
    }

    private static byte[] random16() {
        byte[] b = new byte[16];
        RANDOM.nextBytes(b);
        return b;
    }
}
