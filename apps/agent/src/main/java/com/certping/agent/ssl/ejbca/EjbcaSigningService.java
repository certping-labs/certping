// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Signs a device CSR at the customer's EJBCA.
 *
 * <p>Entry point for the machine-identity path: an MDM or IoT device enrolls over SCEP, the SCEP
 * layer validates the request and hands the CSR here, and this returns the signed certificate.
 *
 * <p>The agent is a pass-through and deliberately imposes no certificate policy of its own. The
 * device supplies the public key, subject and SANs in the CSR; the CA's certificate profile
 * governs everything else — allowed key algorithms and sizes, validity, key usage, EKU — and
 * rejects a CSR that violates it. Those rejections surface as {@code EJBCA_REQUEST_REJECTED}
 * carrying EJBCA's own wording. A permissive CA profile is therefore a real exposure: a stock
 * EJBCA {@code ENDUSER} profile will sign an RSA-512 key and nothing here will stop it.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EjbcaSigningService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String PASSWORD_ALPHABET =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final int PASSWORD_LENGTH = 24;

    private final EjbcaClient client;
    private final EndEntityNameResolver endEntityNameResolver;
    private final AgentProperties properties;

    /**
     * Signs {@code csrPem} and returns the certificate with its chain.
     *
     * @param deviceId stable identifier for the enrolling device, used as the EJBCA end entity
     *                 name; when null it is derived from the CSR
     * @throws PermanentAgentException if configuration is incomplete, the CSR is unusable, or
     *                                 EJBCA rejects the request
     */
    public EjbcaSignResult sign(String csrPem, String deviceId) {
        AgentProperties.EjbcaProperties config = properties.getEjbca();
        requireConfigured(config);
        if (csrPem == null || csrPem.isBlank()) {
            throw new PermanentAgentException("EJBCA_CSR_MISSING", "No CSR supplied for signing");
        }

        String endEntityName = endEntityNameResolver.resolve(csrPem, deviceId, config);
        // The end-entity name resolves from the CSR common name, which for a device enrollment is
        // the device's own identifier. That is a raw identifier value and must not be logged.
        log.debug("EJBCA signing: ca={}, certProfile={}, eeProfile={}",
                config.getCaName(), config.getCertificateProfileName(),
                config.getEndEntityProfileName());

        JsonNode response = client.pkcs10Enroll(buildEnrollBody(csrPem, endEntityName, config));
        return toResult(response, endEntityName);
    }

    /** Reports EJBCA's version and edition, e.g. {@code "EJBCA 9.3.7 Community (afce321...)"}. */
    public String probeVersion() {
        return client.probeVersion();
    }

    /**
     * Effective endpoint for operator display, resolved from the credential rather than the
     * optional {@code agent.ejbca.base-url} override. Null until a session exists.
     */
    public String connectedEndpoint() {
        EjbcaClient.ConnectionInfo info = client.describeConnection();
        return info == null ? null : info.baseUrl();
    }

    /** {@code CLIENT_CERT} or {@code OAUTH_CLIENT_CREDENTIALS}. Null until a session exists. */
    public String activeAuthMethod() {
        EjbcaClient.ConnectionInfo info = client.describeConnection();
        return info == null ? null : info.authMethod();
    }

    private Map<String, Object> buildEnrollBody(String csrPem, String endEntityName,
                                                AgentProperties.EjbcaProperties config) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("certificate_request", csrPem);
        body.put("certificate_profile_name", config.getCertificateProfileName());
        body.put("end_entity_profile_name", config.getEndEntityProfileName());
        body.put("certificate_authority_name", config.getCaName());
        body.put("username", endEntityName);
        // The end entity is created and enrolled in this one authenticated call, so the password
        // is consumed immediately and never reused. It exists because the API demands it —
        // omitting it fails with "400 No Password".
        body.put("password", randomPassword());
        body.put("include_chain", true);
        // "PEM" is rejected with "Response format can only be DER or PKCS7".
        body.put("response_format", "DER");
        return body;
    }

    private EjbcaSignResult toResult(JsonNode response, String endEntityName) {
        String leafBase64 = response.path("certificate").asString(null);
        if (leafBase64 == null || leafBase64.isBlank()) {
            throw new PermanentAgentException("EJBCA_RESPONSE_INVALID",
                    "EJBCA pkcs10enroll response contained no certificate");
        }

        String certificatePem = toPem(leafBase64);
        List<String> chainPem = new ArrayList<>();
        JsonNode chain = response.path("certificate_chain");
        if (chain.isArray()) {
            for (JsonNode node : chain) {
                String value = node.asString("");
                if (!value.isBlank()) {
                    chainPem.add(toPem(value));
                }
            }
        }

        X509Certificate leaf = parseCertificate(leafBase64);
        String serialNumber = response.path("serial_number").asString(null);
        if (serialNumber == null || serialNumber.isBlank()) {
            serialNumber = leaf.getSerialNumber().toString(16).toUpperCase(Locale.ROOT);
        }
        String fullChainPem = chainPem.isEmpty()
                ? certificatePem
                : certificatePem + "\n" + String.join("\n", chainPem);

        // Serial identifies the certificate without naming the device: the subject DN carries the
        // device identifier in its common name.
        log.info("EJBCA signing complete: serial={}, validTo={}", serialNumber, leaf.getNotAfter());

        return new EjbcaSignResult(certificatePem, chainPem, fullChainPem, serialNumber,
                endEntityName, leaf);
    }

    private X509Certificate parseCertificate(String base64Der) {
        try {
            byte[] der = Base64.getDecoder().decode(base64Der.replaceAll("\\s", ""));
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new PermanentAgentException("EJBCA_CERT_PARSE_FAILED",
                    "Could not parse the certificate EJBCA returned: " + e.getMessage(), e);
        }
    }

    private String toPem(String base64Der) {
        String body = base64Der.replaceAll("\\s", "");
        StringBuilder pem = new StringBuilder("-----BEGIN CERTIFICATE-----\n");
        for (int i = 0; i < body.length(); i += 64) {
            pem.append(body, i, Math.min(i + 64, body.length())).append('\n');
        }
        return pem.append("-----END CERTIFICATE-----").toString();
    }

    private String randomPassword() {
        StringBuilder password = new StringBuilder(PASSWORD_LENGTH);
        for (int i = 0; i < PASSWORD_LENGTH; i++) {
            password.append(PASSWORD_ALPHABET.charAt(RANDOM.nextInt(PASSWORD_ALPHABET.length())));
        }
        return password.toString();
    }

    private void requireConfigured(AgentProperties.EjbcaProperties config) {
        if (!config.isEnabled()) {
            throw new PermanentAgentException("EJBCA_DISABLED",
                    "EJBCA signing is disabled. Set agent.ejbca.enabled=true.");
        }
        requireField(config.getCaName(), "agent.ejbca.ca-name");
        requireField(config.getCertificateProfileName(), "agent.ejbca.certificate-profile-name");
        requireField(config.getEndEntityProfileName(), "agent.ejbca.end-entity-profile-name");
    }

    private void requireField(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("EJBCA_CONFIG_MISSING",
                    name + " is required — pkcs10enroll rejects a request that omits it, and "
                            + "there is no safe default.");
        }
    }
}
