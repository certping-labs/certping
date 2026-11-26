// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep.ca;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.scep.RaIdentity;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.ssl.ejbca.EjbcaSignResult;
import com.certping.agent.ssl.ejbca.EjbcaSigningService;
import com.certping.agent.ssl.ejbca.EjbcaRevocationService;
import tools.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * The real SCEP CA backend ({@code agent.scep.ca.backend=ejbca}, the default). A thin adapter over the
 * EJBCA signing driver: it turns the parsed CSR back into PEM, calls
 * {@link EjbcaSigningService#sign(String, String)}, and returns the issued leaf plus chain.
 *
 * <p>The device leaf comes from EJBCA; the RA identity (published via GetCACert, used to decrypt
 * requests and sign the CertRep) is separate CertPing material loaded from the secret store.
 */
@Slf4j
@RequiredArgsConstructor
public class EjbcaScepCaBackend implements ScepCaBackend {

    private final EjbcaSigningService ejbca;
    private final EjbcaRevocationService revocationService;
    private final SecretStore secretStore;
    private final AgentProperties properties;
    private final ObjectMapper objectMapper;

    private RaIdentity ra;

    @PostConstruct
    void loadRa() throws Exception {
        ra = RaIdentity.fromSecret(secretStore, objectMapper,
                properties.getScep().getCa().getRaKeystoreHandle());
        log.info("SCEP RA identity loaded: subject={}", ra.cert().getSubjectX500Principal().getName());
    }

    @Override
    public IssuedCertificate sign(PKCS10CertificationRequest csr, Duration validity) throws CaException {
        try {
            EjbcaSignResult result = ejbca.sign(toPem(csr), null);
            List<X509Certificate> chain = new ArrayList<>();
            chain.add(result.leaf());
            for (String pem : result.chainPem()) {
                chain.add(parse(pem));
            }
            String caName = properties.getEjbca().getCaName();
            return new IssuedCertificate(
                    chain, result.endEntityName(), CaProvider.EJBCA, caName, null);
        } catch (PermanentAgentException e) {
            throw new CaException(e.getMessage(), e);
        } catch (Exception e) {
            throw new CaException("EJBCA signing failed: " + e.getMessage(), e);
        }
    }

    @Override
    public void assertRenewalAllowed(X509Certificate priorCertificate) throws CaException {
        try {
            EjbcaRevocationService.Status status = revocationService.status(
                    priorCertificate.getIssuerX500Principal().getName(),
                    priorCertificate.getSerialNumber().toString(16));
            if (status.revoked()) {
                throw new CaException("The certificate presented for renewal is revoked");
            }
        } catch (CaException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new CaException("Could not verify the renewal certificate's EJBCA revocation status", exception);
        }
    }

    @Override
    public X509Certificate getRaCertificate() {
        return ra.cert();
    }

    @Override
    public PrivateKey getRaPrivateKey() {
        return ra.key();
    }

    @Override
    public List<X509Certificate> getCaChain() {
        return ra.caChain();   // the issuing CA, not the RA leaf that heads the PKCS#12 chain
    }

    private static String toPem(PKCS10CertificationRequest csr) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter w = new JcaPEMWriter(sw)) {
            w.writeObject(csr);
        }
        return sw.toString();
    }

    private static X509Certificate parse(String pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    }
}
