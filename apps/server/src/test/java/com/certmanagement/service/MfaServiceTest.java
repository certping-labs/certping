// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;
import com.certmanagement.entity.UserMfa;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ConflictException;
import com.certmanagement.exception.UnauthorizedException;
import com.certmanagement.repository.UserMfaRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.PepperedPasswordEncoder;
import com.certmanagement.security.Totp;
import com.certmanagement.service.audit.AccessAuditRecorder;
import com.certmanagement.service.audit.AuthAuditRecorder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class MfaServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-25T12:00:00Z");

    private final UserMfaRepository mfaRepository = mock(UserMfaRepository.class);
    private final UserRepository userRepository = mock(UserRepository.class);
    private final AuthAuditRecorder authAudit = mock(AuthAuditRecorder.class);
    private final AccessAuditRecorder accessAudit = mock(AccessAuditRecorder.class);
    private final PepperedPasswordEncoder encoder = new PepperedPasswordEncoder(
            Map.of("v1", Base64.getEncoder().encodeToString(new byte[32])), "v1");
    private final AtomicReference<Instant> clockNow = new AtomicReference<>(NOW);
    private final Clock clock = new Clock() {
        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return clockNow.get(); }
    };

    private MfaService service;
    private User user;
    /** The row the repository hands back, as the service saved it. */
    private final AtomicReference<UserMfa> stored = new AtomicReference<>();

    @BeforeEach
    void setUp() {
        service = new MfaService(mfaRepository, userRepository, encoder, authAudit, accessAudit, clock);
        user = User.builder().id(7).username("ada").email("ada@example.com")
                .passwordHash(encoder.encode("correct horse battery staple"))
                .organization(Organization.builder().id(3L).build()).active(true).build();
        when(userRepository.findById(7)).thenReturn(Optional.of(user));
        when(mfaRepository.findById(7)).thenAnswer(inv -> Optional.ofNullable(stored.get()));
        when(mfaRepository.save(any(UserMfa.class))).thenAnswer(inv -> {
            stored.set(inv.getArgument(0));
            return inv.getArgument(0);
        });
    }

    private byte[] secretOf(UserMfa row) {
        return encoder.open(row.getSecretSealed());
    }

    @Test
    void enrollThenConfirmTurnsTheFactorOnAndHandsOutRecoveryCodesOnce() {
        MfaService.Enrollment enrollment = service.enroll(7);

        assertThat(stored.get()).isNotNull();
        assertThat(stored.get().isConfirmed()).isFalse();
        assertThat(Totp.fromBase32(enrollment.secret())).isEqualTo(secretOf(stored.get()));
        assertThat(enrollment.otpauthUri()).contains("CertPing:ada%40example.com");
        assertThat(service.status(7).enabled()).isFalse();

        String code = Totp.code(secretOf(stored.get()), Totp.step(NOW.getEpochSecond()));
        List<String> recovery = service.confirm(7, code);

        assertThat(recovery).hasSize(MfaService.RECOVERY_CODES).allMatch(c -> c.matches("[a-z2-7]{5}-[a-z2-7]{5}"));
        assertThat(stored.get().isConfirmed()).isTrue();
        assertThat(stored.get().getRecoveryCodeHashes()).doesNotContain(recovery.get(0));
        assertThat(service.status(7)).satisfies(status -> {
            assertThat(status.enabled()).isTrue();
            assertThat(status.recoveryCodesRemaining()).isEqualTo(MfaService.RECOVERY_CODES);
        });
        verify(authAudit).mfaEnabled(any());
    }

    @Test
    void confirmRefusesAWrongCodeAndLeavesTheFactorOff() {
        service.enroll(7);
        assertThatThrownBy(() -> service.confirm(7, "000000")).isInstanceOf(BadRequestException.class);
        assertThat(stored.get().isConfirmed()).isFalse();
        verify(authAudit, never()).mfaEnabled(any());
    }

    @Test
    void enrollIsRefusedWhileTheFactorIsOn() {
        service.enroll(7);
        service.confirm(7, Totp.code(secretOf(stored.get()), Totp.step(NOW.getEpochSecond())));
        assertThatThrownBy(() -> service.enroll(7)).isInstanceOf(ConflictException.class);
    }

    @Test
    void verifyCodeAcceptsEachStepOnceAndSpendsRecoveryCodes() {
        service.enroll(7);
        byte[] secret = secretOf(stored.get());
        List<String> recovery = service.confirm(7, Totp.code(secret, Totp.step(NOW.getEpochSecond())));

        // The confirmation step is spent; the next step is fresh.
        clockNow.set(NOW.plusSeconds(30));
        String next = Totp.code(secret, Totp.step(clockNow.get().getEpochSecond()));
        assertThat(service.verifyCode(7, next)).isTrue();
        assertThat(service.verifyCode(7, next)).as("same code again").isFalse();
        assertThat(service.verifyCode(7, "123456")).isFalse();

        assertThat(service.verifyCode(7, recovery.get(0).toUpperCase())).as("recovery code, any case").isTrue();
        assertThat(service.verifyCode(7, recovery.get(0))).as("recovery code works once").isFalse();
        assertThat(service.status(7).recoveryCodesRemaining()).isEqualTo(MfaService.RECOVERY_CODES - 1);
    }

    @Test
    void verifyCodeIsFalseWithoutAConfirmedFactor() {
        assertThat(service.verifyCode(7, "123456")).isFalse();
        service.enroll(7);
        String code = Totp.code(secretOf(stored.get()), Totp.step(NOW.getEpochSecond()));
        assertThat(service.verifyCode(7, code)).as("unconfirmed enrollment never signs in").isFalse();
    }

    @Test
    void disableNeedsThePasswordAndIsAudited() {
        service.enroll(7);
        service.confirm(7, Totp.code(secretOf(stored.get()), Totp.step(NOW.getEpochSecond())));

        assertThatThrownBy(() -> service.disable(7, "wrong")).isInstanceOf(UnauthorizedException.class);
        verify(mfaRepository, never()).delete(any(UserMfa.class));

        service.disable(7, "correct horse battery staple");
        verify(mfaRepository).delete(stored.get());
        verify(authAudit).mfaDisabled(any());
    }

    @Test
    void resetRemovesTheRowAndAuditsTheMember() {
        service.enroll(7);
        assertThat(service.reset(user)).isTrue();
        verify(mfaRepository).delete(stored.get());
        verify(accessAudit).memberMfaReset(user);

        stored.set(null);
        assertThat(service.reset(user)).isFalse();
    }

    @Test
    void challengeNamesTheUserUntilItExpiresAndRejectsTampering() {
        String token = service.challenge(7);
        assertThat(service.verifyChallenge(token)).contains(7);

        String payload = token.substring(0, token.indexOf('.'));
        String signature = token.substring(token.indexOf('.') + 1);
        String forgedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "8:9999999999:AAAA".getBytes());
        assertThat(service.verifyChallenge(forgedPayload + "." + signature)).isEmpty();
        assertThat(service.verifyChallenge(payload)).isEmpty();
        assertThat(service.verifyChallenge("not a token")).isEmpty();
        assertThat(service.verifyChallenge(null)).isEmpty();

        clockNow.set(NOW.plus(MfaService.CHALLENGE_TTL).plus(Duration.ofSeconds(1)));
        assertThat(service.verifyChallenge(token)).as("expired").isEmpty();
    }

    @Test
    void pepperRotationResealsTheSecretUnderTheActiveVersion() {
        service.enroll(7);
        byte[] secret = secretOf(stored.get());
        String sealedV1 = stored.get().getSecretSealed();

        PepperedPasswordEncoder rotated = new PepperedPasswordEncoder(Map.of(
                "v1", Base64.getEncoder().encodeToString(new byte[32]),
                "v2", Base64.getEncoder().encodeToString(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})), "v2");
        PasswordHashRotationService rotation = new PasswordHashRotationService(userRepository, rotated);
        rotation.setUserMfaRepository(mfaRepository);
        when(mfaRepository.findAll()).thenReturn(List.of(stored.get()));

        assertThat(rotation.resealMfaSecrets(rotated)).isEqualTo(1);
        assertThat(stored.get().getSecretSealed()).isNotEqualTo(sealedV1).startsWith("$enc1$v2$");
        assertThat(rotated.open(stored.get().getSecretSealed())).isEqualTo(secret);
        assertThat(rotation.resealMfaSecrets(rotated)).as("already active").isZero();
    }
}
