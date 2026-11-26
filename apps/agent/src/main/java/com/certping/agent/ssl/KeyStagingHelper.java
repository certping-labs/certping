// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.secrets.SecretStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Shared staging-slot operations for the issuance checkpoint. Keeps the
 * marker-packed serialisation in one place so every CA service stages key+CSR the
 * same way and resume tests in any service see the same format.
 *
 * <p>The staged value is a single KV secret packed as:
 * <pre>
 *   -----BEGIN PRIVATE KEY MARKER-----\n
 *   {keyPem}
 *   \n-----END PRIVATE KEY MARKER-----\n
 *   {csrPem}
 * </pre>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class KeyStagingHelper {

    public static final String STAGING_SLOT_SUFFIX = "-key-staging";
    public static final String STAGED_KEY_MISSING = "STAGED_KEY_MISSING";
    static final Duration MISSING_RETRY_AFTER = Duration.ofSeconds(30);

    private static final String KEY_MARKER = "-----BEGIN PRIVATE KEY MARKER-----";
    private static final String SEPARATOR  = "\n-----END PRIVATE KEY MARKER-----\n";

    private final SecretStore secretStore;

    /** Writes the key+CSR pair to {@code {name}-key-staging} and returns the KV URI. {@code name} is the
     *  certificate's xref, or the xref and the CSR's digest, so two deliveries of one request never
     *  overwrite each other's key. Called once on first issuance attempt, before the billable boundary. */
    public String stage(String name, String privateKeyPem, String csrPem) {
        String slot = name + STAGING_SLOT_SUFFIX;
        String packed = KEY_MARKER + "\n" + privateKeyPem + SEPARATOR + csrPem;
        String handle = secretStore.create(slot, packed);
        log.info("Staged key+csr at {}", handle);
        return handle;
    }

    /**
     * Reads the staged key+CSR back. A corrupt value is a {@link PermanentAgentException}: a fresh key would
     * mismatch the CA's pinned public key. A slot that is gone is retried after a short wait: the attempt's other
     * delivery purges it as it finishes, and the retry then finds that delivery's stored result instead.
     */
    public Staged read(String privateKeyKvPath) {
        String packed;
        try {
            packed = secretStore.read(privateKeyKvPath);
        } catch (PermanentAgentException e) {
            if (!e.getErrorCode().endsWith("_SECRET_NOT_FOUND")) {
                throw e;
            }
            log.warn("Staged key at {} is gone; retrying in {}s to find the result of the delivery that purged it",
                    privateKeyKvPath, MISSING_RETRY_AFTER.toSeconds());
            throw new RetryableAgentException(STAGED_KEY_MISSING,
                    "Staged key at " + privateKeyKvPath + " is gone; another delivery of this attempt may have finished",
                    MISSING_RETRY_AFTER, e);
        }
        if (packed == null || !packed.startsWith(KEY_MARKER)) {
            throw new PermanentAgentException("STAGED_KEY_CORRUPT",
                    "Staged key material at " + privateKeyKvPath + " is missing the marker; "
                            + "cannot resume issuance with a regenerated key");
        }
        String body = packed.substring(KEY_MARKER.length() + 1);
        int sep = body.indexOf(SEPARATOR);
        if (sep < 0) {
            throw new PermanentAgentException("STAGED_KEY_CORRUPT",
                    "Staged key material at " + privateKeyKvPath + " missing separator");
        }
        return new Staged(body.substring(0, sep), body.substring(sep + SEPARATOR.length()));
    }

    /** Best-effort delete. Logged and swallowed on failure; nothing else removes a slot left
     *  behind (see docs/architecture.md#key-custody-and-trust). Never fail the issuance because we couldn't tidy up. */
    public void purge(String privateKeyKvPath) {
        if (privateKeyKvPath == null) return;
        try {
            secretStore.delete(privateKeyKvPath);
            log.info("Purged staging slot {}", privateKeyKvPath);
        } catch (Exception e) {
            log.warn("Staging-slot purge failed for {}; the slot stays in the store: {}",
                    privateKeyKvPath, e.getMessage());
        }
    }

    public record Staged(String privateKeyPem, String csrPem) {}
}
