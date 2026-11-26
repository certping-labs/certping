// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * BCrypt password encoder wrapped in AES-GCM authenticated encryption keyed by
 * one of N application-wide peppers. Supports transparent pepper rotation.
 *
 * <p><b>Design intent:</b> the inner BCrypt hash is encrypted at rest with a key
 * (the "pepper") that lives outside the database. An attacker holding only a DB
 * dump cannot brute-force passwords — they hold only ciphertext.
 *
 * <p><b>Rotation:</b> multiple pepper versions can be live simultaneously so that
 * a rotation can be performed in the background without forcing user resets.
 * During a rotation:
 * <ul>
 *   <li>{@link #encode(CharSequence)} always uses the {@code activeVersion} key.
 *   <li>{@link #matches(CharSequence, String)} reads the embedded version
 *       prefix in each row and selects the matching key.
 *   <li>{@link #reEncrypt(String)} re-wraps a stored hash from its current
 *       version's key to the active version's key — without needing the
 *       user's password. Drive this from a background migration job.
 * </ul>
 *
 * <p><b>Stored-hash format:</b>
 * <pre>$enc1$&lt;pepperVersion&gt;$&lt;url-safe-base64-nonce&gt;$&lt;url-safe-base64-ciphertext&gt;</pre>
 *
 * <ul>
 *   <li>{@code $enc1$} — FORMAT version. Bumped only when the cipher / AAD /
 *       envelope changes (e.g. switching to ChaCha20-Poly1305). Pepper key
 *       rotation does NOT bump this.
 *   <li>{@code pepperVersion} — opaque string (e.g. {@code v1}, {@code v2}).
 *       Selects which key in {@code keysByVersion} to use for decrypt.
 *   <li>{@code nonce} — 12 random bytes, fresh per encode. Never reused with
 *       the same key (GCM rule).
 *   <li>{@code ciphertext} — AES-256-GCM(key=peppers[pepperVersion],
 *       plaintext=bcrypt_hash_utf8, nonce, aad=AAD_V1). 128-bit auth tag
 *       appended by the JCE provider.
 * </ul>
 *
 * <p><b>Operational rules:</b>
 * <ul>
 *   <li>At least one key required and it must be the {@code activeVersion}.
 *       Constructor throws otherwise; the app fails to start.
 *   <li>Each key must decode to exactly 32 bytes (AES-256). Generate with
 *       {@code openssl rand -base64 32}.
 *   <li>To rotate: set the new version's key ({@code PASSWORD_PEPPER_V<n>}), set
 *       {@code PASSWORD_PEPPER_ACTIVE_VERSION} to the new label, deploy. Run
 *       the migration job (see {@code PasswordHashRotationService}). Once the
 *       inventory shows zero rows on the old version, remove the old key
 *       and redeploy.
 *   <li>Never start a new rotation before the previous one fully retired the
 *       old key. The encoder tolerates many live keys; ops should not.
 * </ul>
 */
public class PepperedPasswordEncoder implements PasswordEncoder {

    /** FORMAT version prefix on stored hashes. Independent of pepper version. */
    public static final String ENC_V1_PREFIX = "$enc1$";

    /** BCrypt cost factor 10 — historical default. */
    private static final int BCRYPT_COST = 10;

    private static final String AES_GCM_TRANSFORM = "AES/GCM/NoPadding";
    private static final int GCM_NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int AES_256_KEY_BYTES = 32;

    /** AAD binds ciphertexts to this encoder's format; rejects cross-system reuse. */
    private static final byte[] AAD_V1 =
            "certping:password-hash:enc1".getBytes(StandardCharsets.UTF_8);

    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(BCRYPT_COST);
    private final SecureRandom random = new SecureRandom();

    /** Insertion-ordered so {@link #configuredVersions()} reads the same on every pod and restart. */
    private final Map<String, SecretKeySpec> keysByVersion;
    private final String activeVersion;

    /**
     * @param pepperBase64ByVersion map of pepper version label (e.g. {@code "v1"})
     *                              to base64-encoded 32-byte AES-256 key. Blank
     *                              entries are silently dropped.
     * @param activeVersion         label used for new encodes. Must be a key in
     *                              {@code pepperBase64ByVersion}.
     * @throws IllegalStateException if the map is empty, the active version is
     *                               missing, or any key is the wrong length.
     */
    public PepperedPasswordEncoder(Map<String, String> pepperBase64ByVersion, String activeVersion) {
        if (activeVersion == null || activeVersion.isBlank()) {
            throw new IllegalStateException(
                    "PASSWORD_PEPPER_ACTIVE_VERSION is required (e.g. 'v1').");
        }
        if (pepperBase64ByVersion == null || pepperBase64ByVersion.isEmpty()) {
            throw new IllegalStateException(
                    "At least one PASSWORD_PEPPER_V* must be configured.");
        }

        Map<String, SecretKeySpec> decoded = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : pepperBase64ByVersion.entrySet()) {
            String version = e.getKey();
            String b64 = e.getValue();
            if (b64 == null || b64.isBlank()) {
                continue; // empty slot — pre-declared in yaml but not yet populated
            }
            byte[] raw;
            try {
                raw = Base64.getDecoder().decode(b64.trim());
            } catch (IllegalArgumentException ex) {
                throw new IllegalStateException(
                        "PASSWORD_PEPPER_" + version.toUpperCase() + " is not valid base64.", ex);
            }
            if (raw.length != AES_256_KEY_BYTES) {
                throw new IllegalStateException(
                        "PASSWORD_PEPPER_" + version.toUpperCase()
                                + " must decode to exactly " + AES_256_KEY_BYTES + " bytes (AES-256). Got "
                                + raw.length + ". Regenerate with `openssl rand -base64 32`.");
            }
            decoded.put(version, new SecretKeySpec(raw, "AES"));
        }

        if (!decoded.containsKey(activeVersion)) {
            throw new IllegalStateException(
                    "Active pepper version '" + activeVersion + "' has no key configured. "
                            + "Set PASSWORD-PEPPER-" + activeVersion.toUpperCase()
                            + " in Key Vault, or change PASSWORD-PEPPER-ACTIVE-VERSION.");
        }

        this.keysByVersion = Collections.unmodifiableMap(new LinkedHashMap<>(decoded));
        this.activeVersion = activeVersion;
    }

    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword must not be null");
        }
        String bcryptHash = bcrypt.encode(rawPassword);
        return wrap(bcryptHash.getBytes(StandardCharsets.UTF_8), activeVersion);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String storedHash) {
        if (rawPassword == null || storedHash == null || storedHash.isEmpty()) {
            return false;
        }
        Parsed parsed = tryParse(storedHash);
        if (parsed == null) {
            return false;
        }
        SecretKeySpec key = keysByVersion.get(parsed.pepperVersion);
        if (key == null) {
            // Row references a pepper version we no longer hold. Either the
            // migration retired it prematurely, or this row is from a foreign
            // deployment. Fail closed.
            return false;
        }
        byte[] bcryptHashBytes;
        try {
            bcryptHashBytes = aesGcm(Cipher.DECRYPT_MODE, key, parsed.nonce, parsed.ciphertext);
        } catch (IllegalStateException e) {
            // GCM tag mismatch (wrong key / tampered row). Indistinguishable from
            // wrong-password to the caller, which is what we want.
            return false;
        }
        return bcrypt.matches(rawPassword, new String(bcryptHashBytes, StandardCharsets.UTF_8));
    }

    /**
     * Re-wraps a stored hash so it is encrypted under the current active pepper
     * version. The inner BCrypt hash is recovered using the row's original
     * version key, then re-encrypted with a fresh nonce under the active key.
     * The user's password is never required — this is what enables transparent
     * rotation.
     *
     * <p>Caller (typically {@code PasswordHashRotationService}) is responsible
     * for persisting the returned value back to the row.
     *
     * @param storedHash existing {@code $enc1$<v>$<nonce>$<ct>} value.
     * @return new {@code $enc1$<activeVersion>$<newNonce>$<newCt>} value.
     * @throws IllegalArgumentException if the stored hash is malformed.
     * @throws IllegalStateException    if the embedded version's key is no
     *                                  longer configured (cannot decrypt) or
     *                                  GCM tag verification fails.
     */
    public String reEncrypt(String storedHash) {
        Parsed parsed = tryParse(storedHash);
        if (parsed == null) {
            throw new IllegalArgumentException("Not a valid $enc1$ password hash");
        }
        if (parsed.pepperVersion.equals(activeVersion)) {
            // Already on the active version — nothing to do. Return as-is so the
            // migration job can no-op cheaply if it picks up a stray row.
            return storedHash;
        }
        SecretKeySpec oldKey = keysByVersion.get(parsed.pepperVersion);
        if (oldKey == null) {
            throw new IllegalStateException(
                    "Cannot re-encrypt: pepper version '" + parsed.pepperVersion
                            + "' is no longer configured. Restore PASSWORD-PEPPER-"
                            + parsed.pepperVersion.toUpperCase() + " in Key Vault.");
        }
        byte[] bcryptHashBytes = aesGcm(Cipher.DECRYPT_MODE, oldKey, parsed.nonce, parsed.ciphertext);
        return wrap(bcryptHashBytes, activeVersion);
    }

    /** Currently-configured pepper versions, in declaration order. */
    public Set<String> configuredVersions() {
        return keysByVersion.keySet();
    }

    /** Returns the active pepper version label used for new encodes. */
    public String activeVersion() {
        return activeVersion;
    }

    /** True iff this row's pepper version differs from the active version. */
    public boolean needsReEncrypt(String storedHash) {
        Parsed parsed = tryParse(storedHash);
        return parsed != null && !parsed.pepperVersion.equals(activeVersion);
    }

    /**
     * Seals an account secret that is not a password (a TOTP secret) under the active pepper, in the same
     * {@code $enc1$} envelope the password hashes use, so one key set and one rotation job cover both.
     */
    public String seal(byte[] plaintext) {
        if (plaintext == null) {
            throw new IllegalArgumentException("plaintext must not be null");
        }
        return wrap(plaintext, activeVersion);
    }

    /**
     * The bytes {@link #seal(byte[])} sealed.
     *
     * @throws IllegalStateException when the envelope is malformed, its pepper version is no longer
     *                               configured, or the tag does not verify
     */
    public byte[] open(String sealed) {
        Parsed parsed = tryParse(sealed);
        if (parsed == null) {
            throw new IllegalStateException("Not a valid $enc1$ envelope");
        }
        SecretKeySpec key = keysByVersion.get(parsed.pepperVersion);
        if (key == null) {
            throw new IllegalStateException("Pepper version '" + parsed.pepperVersion + "' is no longer configured");
        }
        return aesGcm(Cipher.DECRYPT_MODE, key, parsed.nonce, parsed.ciphertext);
    }

    /** HMAC-SHA256 of {@code data} under the active pepper, for short-lived tokens that must survive a restart. */
    public byte[] hmac(byte[] data) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(keysByVersion.get(activeVersion).getEncoded(), "HmacSHA256"));
            return mac.doFinal(data);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is unavailable", e);
        }
    }

    /** Builds the stored-hash string from raw BCrypt bytes under the given version. */
    private String wrap(byte[] bcryptHashBytes, String version) {
        byte[] nonce = new byte[GCM_NONCE_BYTES];
        random.nextBytes(nonce);
        byte[] ciphertext = aesGcm(Cipher.ENCRYPT_MODE, keysByVersion.get(version), nonce, bcryptHashBytes);
        return ENC_V1_PREFIX + version + "$" + b64Encode(nonce) + "$" + b64Encode(ciphertext);
    }

    private byte[] aesGcm(int mode, SecretKeySpec key, byte[] nonce, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORM);
            cipher.init(mode, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(AAD_V1);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM operation failed", e);
        }
    }

    private static String b64Encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] b64Decode(String s) {
        return Base64.getUrlDecoder().decode(s);
    }

    /** Parses {@code $enc1$<v>$<nonce>$<ct>}. Returns null on null/empty/format error. */
    private static Parsed tryParse(String storedHash) {
        if (storedHash == null || !storedHash.startsWith(ENC_V1_PREFIX)) return null;
        String body = storedHash.substring(ENC_V1_PREFIX.length());
        // Expect exactly 3 segments separated by '$': version, nonce, ciphertext.
        String[] parts = body.split("\\$", 3);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
            return null;
        }
        byte[] nonce;
        byte[] ciphertext;
        try {
            nonce = b64Decode(parts[1]);
            ciphertext = b64Decode(parts[2]);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (nonce.length != GCM_NONCE_BYTES) return null;
        return new Parsed(parts[0], nonce, ciphertext);
    }

    private record Parsed(String pepperVersion, byte[] nonce, byte[] ciphertext) {}
}
