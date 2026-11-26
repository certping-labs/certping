// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.acme;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.deployment.util.CertificateBundleUtils;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.RevocationReason;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Optional;

/**
 * Revokes a Let's Encrypt certificate using ACME4J.
 *
 * <p>The cert bundle PEM (chain + private key) is read from the secret store by the caller.
 * Idempotent: if the CA reports the cert is already revoked, this returns normally.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LetsEncryptRevocationService {

    private final AgentProperties properties;

    public void revoke(String bundle, String reason) {
        try {
            var parsed = CertificateBundleUtils.parse(bundle);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate x509Cert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(
                            parsed.leafCertificate().getBytes(StandardCharsets.UTF_8)));

            KeyPair certKeyPair = KeyPairUtils.readKeyPair(
                    new StringReader(parsed.privateKey()));

            Session session = new Session(properties.getAcme().getDirectoryUrl());
            RevocationReason revocationReason = mapReason(reason);

            try {
                Certificate.revoke(session, certKeyPair, x509Cert, revocationReason);
                log.info("[LetsEncryptRevocation] Certificate revoked successfully, reason={}", reason);

            } catch (AcmeException e) {
                String msg = e.getMessage() != null ? e.getMessage() : "";
                if (msg.toLowerCase().contains("already revoked")) {
                    log.info("[LetsEncryptRevocation] Certificate already revoked at CA — treating as success");
                    return;
                }
                Optional<RateLimitClassifier.RateLimitVerdict> rl =
                        RateLimitClassifier.classify(e, "CA_PROVIDER_THROTTLED");
                if (rl.isPresent()) {
                    throw rl.get().toRetryable("letsencrypt revocation", "acme-cert", e);
                }
                throw new PermanentAgentException("REVOCATION_FAILED",
                        "ACME revocation rejected: " + msg, e);
            }

        } catch (PermanentAgentException | RetryableAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "CA_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("letsencrypt revocation", "acme-cert", e);
            }
            throw new PermanentAgentException("REVOCATION_FAILED",
                    "Unexpected error revoking LE certificate: " + e.getMessage(), e);
        }
    }

    private RevocationReason mapReason(String reason) {
        if (reason == null) {
            return RevocationReason.UNSPECIFIED;
        }
        return switch (reason.toUpperCase()) {
            case "KEY_COMPROMISE" -> RevocationReason.KEY_COMPROMISE;
            case "CA_COMPROMISE" -> RevocationReason.CA_COMPROMISE;
            case "AFFILIATION_CHANGED" -> RevocationReason.AFFILIATION_CHANGED;
            case "SUPERSEDED" -> RevocationReason.SUPERSEDED;
            case "CESSATION_OF_OPERATION" -> RevocationReason.CESSATION_OF_OPERATION;
            default -> RevocationReason.UNSPECIFIED;
        };
    }
}
