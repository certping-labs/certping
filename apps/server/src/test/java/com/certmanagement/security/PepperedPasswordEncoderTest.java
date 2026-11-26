// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link PepperedPasswordEncoder}. No Spring context — the
 * encoder is a pure, self-contained crypto class.
 *
 * <p>Test keys are fixed 32-byte ASCII values so failures are easy to debug.
 * In production every key is a fresh {@code SecureRandom} 256-bit value.
 */
class PepperedPasswordEncoderTest {

    /** Base64 of "0123456789abcdef0123456789abcdef" — exactly 32 ASCII bytes. */
    private static final String V1_KEY_B64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    /** Base64 of "fedcba9876543210fedcba9876543210" — exactly 32 ASCII bytes. */
    private static final String V2_KEY_B64 = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=";
    /** Base64 of "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef" — exactly 32 ASCII bytes. */
    private static final String V3_KEY_B64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=";

    private static Map<String, String> singleKey() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("v1", V1_KEY_B64);
        return m;
    }

    private static Map<String, String> twoKeys() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("v1", V1_KEY_B64);
        m.put("v2", V2_KEY_B64);
        return m;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor validation
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class Construction {

        @Test
        void throws_whenActiveVersionIsNull() {
            assertThatThrownBy(() -> new PepperedPasswordEncoder(singleKey(), null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("PASSWORD_PEPPER_ACTIVE_VERSION");
        }

        @Test
        void throws_whenActiveVersionIsBlank() {
            assertThatThrownBy(() -> new PepperedPasswordEncoder(singleKey(), "  "))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("PASSWORD_PEPPER_ACTIVE_VERSION");
        }

        @Test
        void throws_whenKeysMapIsNull() {
            assertThatThrownBy(() -> new PepperedPasswordEncoder(null, "v1"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("At least one PASSWORD_PEPPER_V*");
        }

        @Test
        void throws_whenKeysMapIsEmpty() {
            assertThatThrownBy(() -> new PepperedPasswordEncoder(new LinkedHashMap<>(), "v1"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("At least one PASSWORD_PEPPER_V*");
        }

        @Test
        void throws_whenActiveVersionHasNoMatchingKey() {
            // v1 is configured but active points at v2.
            assertThatThrownBy(() -> new PepperedPasswordEncoder(singleKey(), "v2"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Active pepper version 'v2'");
        }

        @Test
        void throws_whenKeyIsInvalidBase64() {
            Map<String, String> bad = new LinkedHashMap<>();
            bad.put("v1", "this is not base 64 !!");
            assertThatThrownBy(() -> new PepperedPasswordEncoder(bad, "v1"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("not valid base64");
        }

        @Test
        void throws_whenKeyIsWrongSize() {
            // 16-byte key (AES-128) instead of 32-byte (AES-256).
            Map<String, String> bad = new LinkedHashMap<>();
            bad.put("v1", "MDEyMzQ1Njc4OWFiY2RlZg=="); // "0123456789abcdef" → 16 bytes
            assertThatThrownBy(() -> new PepperedPasswordEncoder(bad, "v1"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("32 bytes");
        }

        @Test
        void silentlyDropsBlankSlots() {
            // Pre-declared slot with empty value (typical yaml when env var unset).
            Map<String, String> withBlank = new LinkedHashMap<>();
            withBlank.put("v1", V1_KEY_B64);
            withBlank.put("v2", ""); // empty — pre-declared but not yet populated
            withBlank.put("v3", null);

            PepperedPasswordEncoder encoder = new PepperedPasswordEncoder(withBlank, "v1");
            assertThat(encoder.configuredVersions()).containsExactly("v1");
        }

        @Test
        void exposesActiveVersionAndConfiguredVersions() {
            PepperedPasswordEncoder encoder = new PepperedPasswordEncoder(twoKeys(), "v2");
            assertThat(encoder.activeVersion()).isEqualTo("v2");
            assertThat(encoder.configuredVersions()).containsExactlyInAnyOrder("v1", "v2");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // encode() / matches() round-trip
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class EncodeAndMatch {

        @Test
        void encodeProducesStringWithActiveVersionPrefix() {
            PepperedPasswordEncoder encoder = new PepperedPasswordEncoder(twoKeys(), "v2");
            String hash = encoder.encode("hunter2");
            assertThat(hash).startsWith("$enc1$v2$");
        }

        @Test
        void matchesReturnsTrueForCorrectPassword() {
            PepperedPasswordEncoder encoder = new PepperedPasswordEncoder(singleKey(), "v1");
            String hash = encoder.encode("hunter2");
            assertThat(encoder.matches("hunter2", hash)).isTrue();
        }

        @Test
        void matchesReturnsFalseForWrongPassword() {
            PepperedPasswordEncoder encoder = new PepperedPasswordEncoder(singleKey(), "v1");
            String hash = encoder.encode("hunter2");
            assertThat(encoder.matches("Hunter2", hash)).isFalse(); // case differs
            assertThat(encoder.matches("",        hash)).isFalse();
            assertThat(encoder.matches("hunter3", hash)).isFalse();
        }

        @Test
        void sameInputProducesDifferentOutputs() {
            // Both the BCrypt salt and the AES nonce are fresh per call.
            PepperedPasswordEncoder encoder = new PepperedPasswordEncoder(singleKey(), "v1");
            String h1 = encoder.encode("hunter2");
            String h2 = encoder.encode("hunter2");
            assertThat(h1).isNotEqualTo(h2);
            // Both must still verify.
            assertThat(encoder.matches("hunter2", h1)).isTrue();
            assertThat(encoder.matches("hunter2", h2)).isTrue();
        }

        @Test
        void differentPepperKeysProduceIncompatibleHashes() {
            PepperedPasswordEncoder e1 = new PepperedPasswordEncoder(singleKey(), "v1");
            Map<String, String> otherKey = new LinkedHashMap<>();
            otherKey.put("v1", V2_KEY_B64); // same label, DIFFERENT bytes
            PepperedPasswordEncoder e2 = new PepperedPasswordEncoder(otherKey, "v1");

            String h1 = e1.encode("hunter2");
            assertThat(e1.matches("hunter2", h1)).isTrue();
            // e2 has the wrong key for this ciphertext — GCM tag fails → false.
            assertThat(e2.matches("hunter2", h1)).isFalse();
        }

        @Test
        void matchesReturnsFalseForNullOrEmptyInputs() {
            PepperedPasswordEncoder encoder = new PepperedPasswordEncoder(singleKey(), "v1");
            String hash = encoder.encode("hunter2");

            assertThat(encoder.matches(null, hash)).isFalse();
            assertThat(encoder.matches("hunter2", null)).isFalse();
            assertThat(encoder.matches("hunter2", "")).isFalse();
        }

        @Test
        void matchesReturnsFalseForMalformedHash() {
            PepperedPasswordEncoder encoder = new PepperedPasswordEncoder(singleKey(), "v1");
            assertThat(encoder.matches("hunter2", "not even close")).isFalse();
            assertThat(encoder.matches("hunter2", "$enc1$")).isFalse();
            assertThat(encoder.matches("hunter2", "$enc1$v1$")).isFalse();
            assertThat(encoder.matches("hunter2", "$enc1$v1$$")).isFalse();
            assertThat(encoder.matches("hunter2", "$enc1$v1$bad-nonce$bad-ct")).isFalse();
            // Legacy plain-BCrypt format — not supported.
            assertThat(encoder.matches("hunter2",
                    "$2a$10$ezF9D3SR0Iqo0RbPgz6t.uM8aZK7p2vXyqRabcDef9hijkLmnoPqrSt")).isFalse();
        }

        @Test
        void matchesReturnsFalseForUnknownPepperVersion() {
            PepperedPasswordEncoder encoder = new PepperedPasswordEncoder(singleKey(), "v1");
            String hashV1 = encoder.encode("hunter2");
            // Hand-construct a hash that claims version "v9" using v1's payload.
            String swapped = "$enc1$v9$" + hashV1.substring("$enc1$v1$".length());
            assertThat(encoder.matches("hunter2", swapped)).isFalse();
        }

        @Test
        void matchesReturnsFalseForTamperedCiphertext() {
            PepperedPasswordEncoder encoder = new PepperedPasswordEncoder(singleKey(), "v1");
            String hash = encoder.encode("hunter2");
            // Flip a character roughly in the middle of the ciphertext segment.
            // (Avoid the very last char of the base64url string — without padding,
            // its trailing bits may be unused, so flipping it can decode to the
            // same bytes and GCM would still verify, masking the tamper.)
            int sep = hash.lastIndexOf('$');
            int targetIdx = sep + 1 + (hash.length() - sep - 1) / 2;
            char original = hash.charAt(targetIdx);
            char replacement = (original == 'A') ? 'B' : 'A';
            String tampered = hash.substring(0, targetIdx) + replacement + hash.substring(targetIdx + 1);
            assertThat(encoder.matches("hunter2", tampered)).isFalse(); // GCM tag fail
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Multi-version coexistence
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class MultiVersion {

        @Test
        void matchesAcceptsRowsEncryptedUnderAnyConfiguredVersion() {
            // Simulate the middle of a rotation: encoder holds {v1, v2}, active=v2.
            // Old rows are still $enc1$v1$..., new rows are $enc1$v2$..., both must verify.
            PepperedPasswordEncoder onlyV1 = new PepperedPasswordEncoder(singleKey(), "v1");
            String oldRowV1 = onlyV1.encode("hunter2");
            assertThat(oldRowV1).startsWith("$enc1$v1$");

            PepperedPasswordEncoder both = new PepperedPasswordEncoder(twoKeys(), "v2");
            String newRowV2 = both.encode("hunter2");
            assertThat(newRowV2).startsWith("$enc1$v2$");

            // Both verify.
            assertThat(both.matches("hunter2", oldRowV1)).isTrue();
            assertThat(both.matches("hunter2", newRowV2)).isTrue();
        }

        @Test
        void encodeAlwaysUsesActiveVersion() {
            PepperedPasswordEncoder both = new PepperedPasswordEncoder(twoKeys(), "v2");
            for (int i = 0; i < 5; i++) {
                assertThat(both.encode("pw" + i)).startsWith("$enc1$v2$");
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // reEncrypt() — the transparent-rotation primitive
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class ReEncrypt {

        @Test
        void changesVersionLabelToActive() {
            PepperedPasswordEncoder onlyV1 = new PepperedPasswordEncoder(singleKey(), "v1");
            String v1Hash = onlyV1.encode("hunter2");

            PepperedPasswordEncoder both = new PepperedPasswordEncoder(twoKeys(), "v2");
            String v2Hash = both.reEncrypt(v1Hash);

            assertThat(v2Hash).startsWith("$enc1$v2$");
            assertThat(v2Hash).isNotEqualTo(v1Hash);
        }

        @Test
        void preservesPasswordVerifiability() {
            // The whole point: after reEncrypt, the user's password still matches,
            // without the user (or our code) ever seeing the password.
            PepperedPasswordEncoder onlyV1 = new PepperedPasswordEncoder(singleKey(), "v1");
            String v1Hash = onlyV1.encode("hunter2");

            PepperedPasswordEncoder both = new PepperedPasswordEncoder(twoKeys(), "v2");
            String v2Hash = both.reEncrypt(v1Hash);

            assertThat(both.matches("hunter2", v2Hash)).isTrue();
            assertThat(both.matches("Hunter2", v2Hash)).isFalse(); // wrong pw still fails
        }

        @Test
        void isNoOpWhenAlreadyOnActiveVersion() {
            PepperedPasswordEncoder both = new PepperedPasswordEncoder(twoKeys(), "v2");
            String v2Hash = both.encode("hunter2");
            assertThat(both.reEncrypt(v2Hash)).isEqualTo(v2Hash);
        }

        @Test
        void throws_whenSourceVersionKeyIsMissing() {
            // Encoder holds only v2; row is on v1.
            PepperedPasswordEncoder onlyV1 = new PepperedPasswordEncoder(singleKey(), "v1");
            String v1Hash = onlyV1.encode("hunter2");

            Map<String, String> onlyV2 = new LinkedHashMap<>();
            onlyV2.put("v2", V2_KEY_B64);
            PepperedPasswordEncoder onlyV2Encoder = new PepperedPasswordEncoder(onlyV2, "v2");

            assertThatThrownBy(() -> onlyV2Encoder.reEncrypt(v1Hash))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("pepper version 'v1'");
        }

        @Test
        void throws_onMalformedInput() {
            PepperedPasswordEncoder both = new PepperedPasswordEncoder(twoKeys(), "v2");
            assertThatThrownBy(() -> both.reEncrypt("not a hash"))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void multiStepRotationChainStillVerifies() {
            // v1 → v2 → v3 round trip. Password should verify at every stage.
            PepperedPasswordEncoder onlyV1 = new PepperedPasswordEncoder(singleKey(), "v1");
            String row = onlyV1.encode("hunter2");
            assertThat(row).startsWith("$enc1$v1$");

            // Rotation 1: v1 → v2.
            PepperedPasswordEncoder v1AndV2 = new PepperedPasswordEncoder(twoKeys(), "v2");
            row = v1AndV2.reEncrypt(row);
            assertThat(row).startsWith("$enc1$v2$");
            assertThat(v1AndV2.matches("hunter2", row)).isTrue();

            // Retire v1, then rotate v2 → v3.
            Map<String, String> v2AndV3 = new LinkedHashMap<>();
            v2AndV3.put("v2", V2_KEY_B64);
            v2AndV3.put("v3", V3_KEY_B64);
            PepperedPasswordEncoder rotator = new PepperedPasswordEncoder(v2AndV3, "v3");
            row = rotator.reEncrypt(row);
            assertThat(row).startsWith("$enc1$v3$");
            assertThat(rotator.matches("hunter2", row)).isTrue();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // needsReEncrypt() — the migration job's filter
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class NeedsReEncrypt {

        @Test
        void returnsFalse_whenAlreadyOnActiveVersion() {
            PepperedPasswordEncoder encoder = new PepperedPasswordEncoder(twoKeys(), "v2");
            String v2Hash = encoder.encode("hunter2");
            assertThat(encoder.needsReEncrypt(v2Hash)).isFalse();
        }

        @Test
        void returnsTrue_whenRowIsOnOlderVersion() {
            PepperedPasswordEncoder onlyV1 = new PepperedPasswordEncoder(singleKey(), "v1");
            String v1Hash = onlyV1.encode("hunter2");

            PepperedPasswordEncoder rotated = new PepperedPasswordEncoder(twoKeys(), "v2");
            assertThat(rotated.needsReEncrypt(v1Hash)).isTrue();
        }

        @Test
        void returnsFalse_forMalformedInput() {
            PepperedPasswordEncoder encoder = new PepperedPasswordEncoder(twoKeys(), "v2");
            assertThat(encoder.needsReEncrypt(null)).isFalse();
            assertThat(encoder.needsReEncrypt("")).isFalse();
            assertThat(encoder.needsReEncrypt("$2a$10$legacy")).isFalse();
        }
    }
}
