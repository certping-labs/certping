// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.entity.User;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.PepperedPasswordEncoder;
import com.certmanagement.service.PasswordHashRotationService.BatchSummary;
import com.certmanagement.service.PasswordHashRotationService.InventoryReport;
import com.certmanagement.service.PasswordHashRotationService.RotationReport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link PasswordHashRotationService}. Uses a REAL
 * {@link PepperedPasswordEncoder} (it's pure crypto; mocking it would obscure
 * round-trip correctness) and a MOCK {@link UserRepository}.
 */
@ExtendWith(MockitoExtension.class)
class PasswordHashRotationServiceTest {

    /** Two fixed test keys; identical pattern to PepperedPasswordEncoderTest. */
    private static final String V1_KEY_B64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    private static final String V2_KEY_B64 = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=";

    @Mock private UserRepository userRepository;

    /** Encoder for "before rotation" world: only v1 exists, active=v1. */
    private PepperedPasswordEncoder onlyV1Encoder;

    /** Encoder for "mid rotation" world: v1+v2 live, active=v2. */
    private PepperedPasswordEncoder midRotationEncoder;

    /** Service under test, wired with the mid-rotation encoder by default. */
    private PasswordHashRotationService service;

    @BeforeEach
    void setUp() {
        Map<String, String> v1Only = new LinkedHashMap<>();
        v1Only.put("v1", V1_KEY_B64);
        onlyV1Encoder = new PepperedPasswordEncoder(v1Only, "v1");

        Map<String, String> both = new LinkedHashMap<>();
        both.put("v1", V1_KEY_B64);
        both.put("v2", V2_KEY_B64);
        midRotationEncoder = new PepperedPasswordEncoder(both, "v2");

        service = new PasswordHashRotationService(userRepository, midRotationEncoder);
    }

    /** Builds a user with a real hash produced by the given encoder. */
    private User userWithHash(int id, PepperedPasswordEncoder enc, String pw) {
        return User.builder()
                .id(id)
                .email("u" + id + "@test.local")
                .passwordHash(enc.encode(pw))
                .build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // inventory()
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class Inventory {

        @Test
        void includesActiveVersionAndCountPerConfiguredVersion() {
            when(userRepository.countByPasswordHashStartingWith("$enc1$v1$")).thenReturn(7L);
            when(userRepository.countByPasswordHashStartingWith("$enc1$v2$")).thenReturn(3L);

            InventoryReport inv = service.inventory();

            assertThat(inv.activeVersion()).isEqualTo("v2");
            assertThat(inv.counts())
                    .hasSize(2)
                    .containsEntry("v1", 7L)
                    .containsEntry("v2", 3L);
        }

        @Test
        void reportsZeroWhenNoRowsExistOnAVersion() {
            when(userRepository.countByPasswordHashStartingWith(anyString())).thenReturn(0L);

            InventoryReport inv = service.inventory();
            assertThat(inv.activeVersion()).isEqualTo("v2");
            assertThat(inv.counts())
                    .hasSize(2)
                    .containsEntry("v1", 0L)
                    .containsEntry("v2", 0L);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // migrateBatch()  (package-private internal building block)
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class MigrateBatch {

        @Test
        void returnsZeroWhenFromVersionEqualsActive() {
            BatchSummary result = service.migrateBatch("v2", 100);
            assertThat(result.migrated()).isZero();
            assertThat(result.skipped()).isZero();
            verify(userRepository, never()).findByPasswordHashStartingWith(anyString(), any());
        }

        @Test
        void rewrapsRowsAndPersistsThem() {
            List<User> rows = List.of(
                    userWithHash(1, onlyV1Encoder, "pw-alpha"),
                    userWithHash(2, onlyV1Encoder, "pw-beta"),
                    userWithHash(3, onlyV1Encoder, "pw-gamma"));
            when(userRepository.findByPasswordHashStartingWith(eqPrefix("v1"), any(Pageable.class)))
                    .thenReturn(rows);

            BatchSummary result = service.migrateBatch("v1", 100);
            assertThat(result.migrated()).isEqualTo(3);
            assertThat(result.skipped()).isZero();

            ArgumentCaptor<List<User>> saved = ArgumentCaptor.forClass(List.class);
            verify(userRepository).saveAll(saved.capture());
            assertThat(saved.getValue()).hasSize(3);
            assertThat(saved.getValue().get(0).getPasswordHash()).startsWith("$enc1$v2$");
            assertThat(midRotationEncoder.matches("pw-alpha", saved.getValue().get(0).getPasswordHash())).isTrue();
            assertThat(midRotationEncoder.matches("pw-beta",  saved.getValue().get(1).getPasswordHash())).isTrue();
            assertThat(midRotationEncoder.matches("pw-gamma", saved.getValue().get(2).getPasswordHash())).isTrue();
        }

        @Test
        void skipsBadRowsAndReportsSkippedCount() {
            // Mixed batch: two valid + one with a malformed payload.
            User good1 = userWithHash(1, onlyV1Encoder, "pw1");
            User badV1 = User.builder()
                    .id(2).email("x")
                    .passwordHash("$enc1$v1$invalid$invalid")
                    .build();
            User good2 = userWithHash(3, onlyV1Encoder, "pw3");

            when(userRepository.findByPasswordHashStartingWith(eqPrefix("v1"), any(Pageable.class)))
                    .thenReturn(new ArrayList<>(List.of(good1, badV1, good2)));

            BatchSummary result = service.migrateBatch("v1", 100);

            assertThat(result.migrated()).isEqualTo(2);
            assertThat(result.skipped()).isEqualTo(1);
            verify(userRepository).saveAll(any());
        }

        @Test
        void respectsBatchSize() {
            List<User> oneRow = List.of(userWithHash(1, onlyV1Encoder, "pw"));
            when(userRepository.findByPasswordHashStartingWith(eqPrefix("v1"), any(Pageable.class)))
                    .thenReturn(oneRow);

            BatchSummary result = service.migrateBatch("v1", 1);
            assertThat(result.migrated()).isEqualTo(1);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // drainVersion() — looping a single source version to completion
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class DrainVersion {

        @Test
        void loopsUntilRemainingCountHitsZero() {
            // 3 rows on v1. Batch size 2 → batch 1 migrates 2, batch 2 migrates 1, done.
            AtomicInteger remaining = new AtomicInteger(3);
            when(userRepository.countByPasswordHashStartingWith(eqPrefix("v1")))
                    .thenAnswer(inv -> (long) remaining.get());

            AtomicInteger batchCall = new AtomicInteger();
            when(userRepository.findByPasswordHashStartingWith(eqPrefix("v1"), any(Pageable.class)))
                    .thenAnswer(inv -> {
                        int call = batchCall.incrementAndGet();
                        if (call == 1) {
                            remaining.addAndGet(-2);
                            return List.of(
                                    userWithHash(1, onlyV1Encoder, "a"),
                                    userWithHash(2, onlyV1Encoder, "b"));
                        }
                        remaining.addAndGet(-1);
                        return List.of(userWithHash(3, onlyV1Encoder, "c"));
                    });

            BatchSummary result = service.drainVersion("v1", 2);
            assertThat(result.migrated()).isEqualTo(3);
            assertThat(result.skipped()).isZero();
        }

        @Test
        void shortCircuitsWhenAlreadyEmpty() {
            when(userRepository.countByPasswordHashStartingWith(eqPrefix("v1"))).thenReturn(0L);
            BatchSummary result = service.drainVersion("v1", 100);
            assertThat(result.migrated()).isZero();
            verify(userRepository, never()).findByPasswordHashStartingWith(anyString(), any());
        }

        @Test
        void shortCircuitsWhenFromEqualsActive() {
            BatchSummary result = service.drainVersion("v2", 100);
            assertThat(result.migrated()).isZero();
            verify(userRepository, never()).countByPasswordHashStartingWith(anyString());
        }

        @Test
        void abortsOnStall_whenBatchMakesNoProgress() {
            // Repo always reports the same `remaining` count, and every row in
            // the batch is malformed (always skipped). Without stall detection
            // this would loop forever — the stall guard must stop it.
            when(userRepository.countByPasswordHashStartingWith(eqPrefix("v1"))).thenReturn(2L);
            User bad1 = User.builder().id(1).email("a").passwordHash("$enc1$v1$bad$bad").build();
            User bad2 = User.builder().id(2).email("b").passwordHash("$enc1$v1$bad$bad").build();
            when(userRepository.findByPasswordHashStartingWith(eqPrefix("v1"), any(Pageable.class)))
                    .thenReturn(List.of(bad1, bad2));

            BatchSummary result = service.drainVersion("v1", 2);

            // We expect exactly ONE batch (the stall is detected after it).
            verify(userRepository, times(1)).findByPasswordHashStartingWith(anyString(), any());
            assertThat(result.migrated()).isZero();
            assertThat(result.skipped()).isEqualTo(2);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // rotateAllToActive() — the public aggregator
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class RotateAllToActive {

        @Test
        void drainsEveryNonActiveVersion() {
            // Encoder has {v1, v2} with active=v2. v1 has 2 rows, v2 has 0 → only v1 to drain.
            when(userRepository.countByPasswordHashStartingWith(eqPrefix("v1")))
                    .thenReturn(2L, 0L);   // before drain, after drain
            when(userRepository.countByPasswordHashStartingWith(eqPrefix("v2")))
                    .thenReturn(2L);       // post-state count
            when(userRepository.findByPasswordHashStartingWith(eqPrefix("v1"), any(Pageable.class)))
                    .thenReturn(List.of(
                            userWithHash(1, onlyV1Encoder, "a"),
                            userWithHash(2, onlyV1Encoder, "b")));

            RotationReport report = service.rotateAllToActive(500);

            assertThat(report.activeVersion()).isEqualTo("v2");
            assertThat(report.migrated()).isEqualTo(2);
            assertThat(report.skipped()).isZero();
            assertThat(report.byVersion()).containsExactly(Map.entry("v1", 2));
            assertThat(report.inventoryAfter()).containsEntry("v1", 0L).containsEntry("v2", 2L);
        }

        @Test
        void skipsActiveVersion_andReportsZeroWhenNoOldRows() {
            when(userRepository.countByPasswordHashStartingWith(eqPrefix("v1"))).thenReturn(0L);
            when(userRepository.countByPasswordHashStartingWith(eqPrefix("v2"))).thenReturn(5L);

            RotationReport report = service.rotateAllToActive(500);

            assertThat(report.migrated()).isZero();
            assertThat(report.skipped()).isZero();
            assertThat(report.byVersion()).isEmpty();
            // Never queries v2 rows for migration — it's the active version.
            verify(userRepository, never()).findByPasswordHashStartingWith(anyString(), any());
        }

        @Test
        void throws_onNonPositiveBatchSize() {
            assertThatThrownBy(() -> service.rotateAllToActive(0))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> service.rotateAllToActive(-5))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void throws_onBatchSizeAboveTheCap() {
            assertThatThrownBy(() -> service.rotateAllToActive(PasswordHashRotationService.MAX_BATCH_SIZE + 1))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("between 1 and 1000");
            assertThatThrownBy(() -> service.rotateAllToActive(100_000_000))
                    .isInstanceOf(IllegalArgumentException.class);
            verify(userRepository, never()).findByPasswordHashStartingWith(anyString(), any());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Encoder type guard
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class EncoderGuard {

        @Test
        void throws_whenInjectedEncoderIsNotPepperedPasswordEncoder() {
            PasswordEncoder unrelated = new PasswordEncoder() {
                @Override public String encode(CharSequence raw) { return "fake"; }
                @Override public boolean matches(CharSequence raw, String enc) { return false; }
            };
            PasswordHashRotationService svc = new PasswordHashRotationService(userRepository, unrelated);

            assertThatThrownBy(svc::inventory).isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("PepperedPasswordEncoder");
            assertThatThrownBy(() -> svc.rotateAllToActive(100))
                    .isInstanceOf(IllegalStateException.class);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private static String eqPrefix(String version) {
        return org.mockito.ArgumentMatchers.eq("$enc1$" + version + "$");
    }
}
