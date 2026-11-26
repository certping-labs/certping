// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.util;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.exception.PermanentAgentException;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses the raw PEM bundle the issuance services store in the secret store into a {@link CertificateBundle}.
 *
 * Bundle format (written by LetsEncryptAcmeService / DigiCertIssuanceService):
 * <pre>
 *   -----BEGIN CERTIFICATE-----   ← leaf cert
 *   ...
 *   -----END CERTIFICATE-----
 *   -----BEGIN CERTIFICATE-----   ← intermediate(s)
 *   ...
 *   -----END CERTIFICATE-----
 *   -----BEGIN [RSA] PRIVATE KEY-----
 *   ...
 *   -----END [RSA] PRIVATE KEY-----
 * </pre>
 *
 * Order: certificates first, private key last, which matches the acme4j and DigiCert output.
 */
public class CertificateBundleUtils {

    private static final Pattern CERT_BLOCK_PATTERN = Pattern.compile(
            "-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----",
            Pattern.DOTALL);

    private static final Pattern KEY_BLOCK_PATTERN = Pattern.compile(
            "-----BEGIN (?:RSA |EC )?PRIVATE KEY-----.+?-----END (?:RSA |EC )?PRIVATE KEY-----",
            Pattern.DOTALL);

    private CertificateBundleUtils() {}

    /**
     * Parse a raw PEM bundle into its components.
     *
     * @throws PermanentAgentException with errorCode {@code CERT_FORMAT_INVALID} if the bundle
     *         does not contain at least one certificate and one private key block
     */
    public static CertificateBundle parse(String rawBundle) {
        if (rawBundle == null || rawBundle.isBlank()) {
            throw new PermanentAgentException("CERT_FORMAT_INVALID",
                    "PEM bundle read from KV is blank");
        }

        // Extract private key
        Matcher keyMatcher = KEY_BLOCK_PATTERN.matcher(rawBundle);
        if (!keyMatcher.find()) {
            throw new PermanentAgentException("CERT_FORMAT_INVALID",
                    "No private key block found in PEM bundle");
        }
        String privateKey = keyMatcher.group().trim();

        // Extract all certificate blocks
        List<String> certBlocks = new ArrayList<>();
        Matcher certMatcher = CERT_BLOCK_PATTERN.matcher(rawBundle);
        while (certMatcher.find()) {
            certBlocks.add(certMatcher.group().trim());
        }

        if (certBlocks.isEmpty()) {
            throw new PermanentAgentException("CERT_FORMAT_INVALID",
                    "No certificate blocks found in PEM bundle");
        }

        // Leaf = first cert block
        String leafCertificate = certBlocks.get(0);

        // Chain = all certs except leaf (intermediates + root) — required by AWS ACM
        String certChain = "";
        if (certBlocks.size() > 1) {
            StringBuilder chainBuilder = new StringBuilder();
            for (int i = 1; i < certBlocks.size(); i++) {
                chainBuilder.append(certBlocks.get(i)).append("\n");
            }
            certChain = chainBuilder.toString().trim();
        }

        // Full chain = all cert blocks (leaf + intermediates + root) — required by Azure KV
        StringBuilder fullChainBuilder = new StringBuilder();
        for (String cert : certBlocks) {
            fullChainBuilder.append(cert).append("\n");
        }
        String fullChain = fullChainBuilder.toString().trim();

        return new CertificateBundle(privateKey, leafCertificate, certChain, fullChain);
    }
}
