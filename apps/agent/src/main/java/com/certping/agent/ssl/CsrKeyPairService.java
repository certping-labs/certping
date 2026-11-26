// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import com.certping.agent.exception.PermanentAgentException;
import lombok.extern.slf4j.Slf4j;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.springframework.stereotype.Service;

import java.io.StringWriter;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

/**
 * Generates RSA-2048 key pairs and PKCS10 CSRs for certificate issuance.
 * Generates CSR key pairs. No entity or repository dependencies.
 *
 * Used by both LetsEncryptAcmeService (ACME finalize) and DigiCertIssuanceService.
 */
@Slf4j
@Service
public class CsrKeyPairService {

    private static final int MAX_COMMON_NAME_LENGTH = 64;

    /** Generate a new RSA-2048 key pair (for the certificate, not the ACME account). */
    public KeyPair generateKeyPair() {
        return KeyPairUtils.createKeyPair(2048);
    }

    /**
     * Generate a key pair based on policy-derived key type and size.
     * Supports RSA and ECDSA.
     */
    public KeyPair generateKeyPair(String keyType, Integer keySize) {
        String normalizedType = keyType != null ? keyType.trim().toUpperCase() : "RSA";
        int size = keySize != null ? keySize : 2048;

        return switch (normalizedType) {
            case "RSA" -> KeyPairUtils.createKeyPair(size);
            case "ECDSA" -> KeyPairUtils.createECKeyPair(ecCurveForSize(size));
            default -> throw new PermanentAgentException("CSR_KEYTYPE_UNSUPPORTED",
                    "Unsupported key type for CSR generation: " + normalizedType);
        };
    }

    /**
     * Build and sign a CSR for the given domains.
     *
     * @param domains first element is CN; remaining are SANs
     * @param keyPair key pair to sign the CSR
     */
    public CSRBuilder buildCsr(List<String> domains, KeyPair keyPair) {
        try {
            CSRBuilder csrBuilder = new CSRBuilder();
            for (String domain : domains) {
                csrBuilder.addDomain(domain);
            }
            // acme4j puts the names in the SAN only. Commercial CAs check the CSR's CN against the order's
            // commonName; a name over 64 characters cannot be a CN and stays in the SAN alone.
            if (!domains.isEmpty() && domains.get(0).length() <= MAX_COMMON_NAME_LENGTH) {
                csrBuilder.setCommonName(domains.get(0));
            }
            csrBuilder.sign(keyPair);
            return csrBuilder;
        } catch (Exception e) {
            throw new PermanentAgentException("CSR_BUILD_FAILED",
                    "Failed to build CSR: " + e.getMessage(), e);
        }
    }

    /**
     * Generate a key pair and signed CSR in one call.
     *
     * @param commonName primary domain (CN)
     * @param sanDomains optional SANs
     * @return {@link CsrKeyPairResult} with PEM-serialized CSR and private key
     */
    public CsrKeyPairResult generateCsrAndKeyPair(String commonName, List<String> sanDomains) {
        List<String> domains = new ArrayList<>();
        domains.add(commonName);
        if (sanDomains != null && !sanDomains.isEmpty()) {
            domains.addAll(sanDomains);
        }

        KeyPair keyPair = generateKeyPair();
        CSRBuilder csrBuilder = buildCsr(domains, keyPair);

        try {
            StringWriter csrWriter = new StringWriter();
            csrBuilder.write(csrWriter);

            StringWriter keyWriter = new StringWriter();
            KeyPairUtils.writeKeyPair(keyPair, keyWriter);

            log.debug("Generated CSR + KeyPair for CN={}, SANs={}", commonName, sanDomains);
            return new CsrKeyPairResult(csrBuilder.getEncoded(), csrWriter.toString(), keyWriter.toString());

        } catch (Exception e) {
            throw new PermanentAgentException("CSR_SERIALIZE_FAILED",
                    "Failed to serialize CSR/key: " + e.getMessage(), e);
        }
    }

    /**
     * Generate a key pair and signed CSR using policy-derived key parameters.
     */
    public CsrKeyPairResult generateCsrAndKeyPair(String commonName,
                                                  List<String> sanDomains,
                                                  String keyType,
                                                  Integer keySize) {
        List<String> domains = new ArrayList<>();
        domains.add(commonName);
        if (sanDomains != null && !sanDomains.isEmpty()) {
            domains.addAll(sanDomains);
        }

        KeyPair keyPair = generateKeyPair(keyType, keySize);
        CSRBuilder csrBuilder = buildCsr(domains, keyPair);

        try {
            StringWriter csrWriter = new StringWriter();
            csrBuilder.write(csrWriter);

            StringWriter keyWriter = new StringWriter();
            KeyPairUtils.writeKeyPair(keyPair, keyWriter);

            log.debug("Generated policy-based CSR + KeyPair for CN={}, SANs={}, keyType={}, keySize={}",
                    commonName, sanDomains, keyType, keySize);
            return new CsrKeyPairResult(csrBuilder.getEncoded(), csrWriter.toString(), keyWriter.toString());

        } catch (Exception e) {
            throw new PermanentAgentException("CSR_SERIALIZE_FAILED",
                    "Failed to serialize CSR/key: " + e.getMessage(), e);
        }
    }

    private String ecCurveForSize(int keySize) {
        return switch (keySize) {
            case 256 -> "secp256r1";
            case 384 -> "secp384r1";
            case 521 -> "secp521r1";
            default -> throw new PermanentAgentException("CSR_EC_KEYSIZE_UNSUPPORTED",
                    "Unsupported ECDSA key size for CSR generation: " + keySize);
        };
    }

    /**
     * Immutable result: DER-encoded CSR bytes, CSR PEM, and private key PEM.
     */
    public record CsrKeyPairResult(byte[] csrDer, String csrPem, String privateKeyPem) {}
}
