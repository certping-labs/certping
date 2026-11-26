// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.validation;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The rules here come from querying a live Intune tenant, not from the Graph docs — several
 * of them contradict the documentation. Each test names the observation it protects.
 */
class DeviceFieldNormalizerTest {

    private final DeviceFieldNormalizer normalizer = new DeviceFieldNormalizer();

    // ── text ────────────────────────────────────────────────────────────────

    @Test
    void text_keepsARealValue() {
        assertThat(normalizer.text("FF29MV4534")).isEqualTo("FF29MV4534");
    }

    @Test
    void text_trims() {
        assertThat(normalizer.text("  FF29MV4534  ")).isEqualTo("FF29MV4534");
    }

    /** A stale enrollment returns serialNumber:"" — storing that breaks the device match key. */
    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "\t", "\n"})
    void text_blankBecomesNull(String blank) {
        assertThat(normalizer.text(blank)).isNull();
    }

    @Test
    void text_nullStaysNull() {
        assertThat(normalizer.text(null)).isNull();
    }

    /** "Unknown" is a real jailbreak reading, so plain text() must not strip it. */
    @Test
    void text_keepsUnknown() {
        assertThat(normalizer.text("Unknown")).isEqualTo("Unknown");
    }

    /** deviceName carried a Unicode curly apostrophe on the live tenant. */
    @Test
    void text_preservesNonAscii() {
        assertThat(normalizer.text("Alex’s MacBook Air")).isEqualTo("Alex’s MacBook Air");
    }

    // ── textOrSentinel ──────────────────────────────────────────────────────

    /** Graph reports "Unknown" for device category and "0.0.0.0" for an unreported OS version. */
    @ParameterizedTest
    @ValueSource(strings = {"Unknown", "unknown", "UNKNOWN", "0.0.0.0", "none", "None"})
    void textOrSentinel_placeholdersBecomeNull(String sentinel) {
        assertThat(normalizer.textOrSentinel(sentinel)).isNull();
    }

    @Test
    void textOrSentinel_keepsARealOsVersion() {
        assertThat(normalizer.textOrSentinel("15.6.1")).isEqualTo("15.6.1");
    }

    /** "none" is a sentinel; a value that merely contains it is not. */
    @Test
    void textOrSentinel_doesNotMatchOnSubstring() {
        assertThat(normalizer.textOrSentinel("none-such-model")).isEqualTo("none-such-model");
    }

    // ── guid ────────────────────────────────────────────────────────────────

    /**
     * The stale Windows device reported an all-zero azureADDeviceId. Storing it would attach one
     * shared key to every un-registered device, and the unique index on
     * (org, key_type, key_value) would then collide them onto a single row.
     */
    @Test
    void guid_zeroGuidBecomesNull() {
        assertThat(normalizer.guid("00000000-0000-0000-0000-000000000000")).isNull();
    }

    @Test
    void guid_zeroGuidIsCaseInsensitive() {
        assertThat(normalizer.guid("00000000-0000-0000-0000-000000000000".toUpperCase())).isNull();
    }

    @Test
    void guid_keepsARealGuid() {
        String id = "8f3c1b2a-4d5e-6f70-8192-a3b4c5d6e7f8";
        assertThat(normalizer.guid(id)).isEqualTo(id);
    }

    @Test
    void guid_blankBecomesNull() {
        assertThat(normalizer.guid("")).isNull();
    }

    // ── timestamp ───────────────────────────────────────────────────────────

    /** lastSyncDateTime on a never-synced enrollment. */
    @Test
    void timestamp_minSentinelBecomesNull() {
        assertThat(normalizer.timestamp(OffsetDateTime.parse("0001-01-01T00:00:00Z"))).isNull();
    }

    /** complianceGracePeriodExpirationDateTime when no grace period applies. */
    @Test
    void timestamp_maxSentinelBecomesNull() {
        assertThat(normalizer.timestamp(OffsetDateTime.parse("9999-12-31T23:59:59Z"))).isNull();
    }

    /**
     * The collection endpoint returns second precision, a single-device GET returns sub-second.
     * Untruncated, the same unchanged device diffs as changed depending on which call fetched
     * it — so "no change, no event" never fires and every sync writes an event for every device.
     */
    @Test
    void timestamp_truncatesSubSecondPrecision() {
        OffsetDateTime fromGet = OffsetDateTime.parse("2026-08-12T06:16:04.0600932Z");
        assertThat(normalizer.timestamp(fromGet))
                .isEqualTo(OffsetDateTime.of(2026, 8, 12, 6, 16, 4, 0, ZoneOffset.UTC));
    }

    @Test
    void timestamp_listAndGetFormsCompareEqualAfterNormalising() {
        OffsetDateTime fromList = OffsetDateTime.parse("2026-08-12T06:16:04Z");
        OffsetDateTime fromGet  = OffsetDateTime.parse("2026-08-12T06:16:04.0600932Z");

        assertThat(normalizer.changed(normalizer.timestamp(fromList), normalizer.timestamp(fromGet)))
                .isFalse();
    }

    @Test
    void timestamp_nullStaysNull() {
        assertThat(normalizer.timestamp(null)).isNull();
    }

    // ── ownerType ───────────────────────────────────────────────────────────

    /** Graph returns company / personal / unknown in lower case. */
    @Test
    void ownerType_upperCases() {
        assertThat(normalizer.ownerType("company")).isEqualTo("COMPANY");
        assertThat(normalizer.ownerType("personal")).isEqualTo("PERSONAL");
    }

    @Test
    void ownerType_blankBecomesNull() {
        assertThat(normalizer.ownerType("  ")).isNull();
    }

    // ── changed ─────────────────────────────────────────────────────────────

    @Test
    void changed_bothNullIsNoChange() {
        assertThat(normalizer.changed(null, null)).isFalse();
    }

    @Test
    void changed_sameValueIsNoChange() {
        assertThat(normalizer.changed("COMPLIANT", "COMPLIANT")).isFalse();
    }

    @Test
    void changed_differentValueIsAChange() {
        assertThat(normalizer.changed("COMPLIANT", "NON_COMPLIANT")).isTrue();
    }

    @Test
    void changed_appearingIsAChange() {
        assertThat(normalizer.changed(null, "COMPLIANT")).isTrue();
    }

    @Test
    void changed_disappearingIsAChange() {
        assertThat(normalizer.changed("COMPLIANT", null)).isTrue();
    }

    /** Booleans and enums go through the same comparison as strings. */
    @Test
    void changed_worksForNonStrings() {
        assertThat(normalizer.changed(Boolean.TRUE, Boolean.TRUE)).isFalse();
        assertThat(normalizer.changed(Boolean.TRUE, Boolean.FALSE)).isTrue();
    }

    /**
     * The whole point of normalising before diffing: null, "" and "Unknown" all mean "absent",
     * so a device reporting them in different ways across two syncs must not look changed.
     */
    @Test
    void changed_isFalseAcrossTheThreeWaysGraphSaysNothing() {
        assertThat(normalizer.changed(normalizer.text(""), normalizer.text(null))).isFalse();
        assertThat(normalizer.changed(
                normalizer.textOrSentinel("Unknown"), normalizer.textOrSentinel(""))).isFalse();
    }
}
