// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.entity.User;
import com.certmanagement.entity.UserMfa;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ConflictException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.exception.UnauthorizedException;
import com.certmanagement.repository.UserMfaRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.PepperedPasswordEncoder;
import com.certmanagement.security.SignInAccount;
import com.certmanagement.security.Totp;
import com.certmanagement.service.audit.AccessAuditRecorder;
import com.certmanagement.service.audit.AuthAuditRecorder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * TOTP second factor for local accounts.
 *
 * <p>Enrollment is two steps: {@link #enroll} makes a secret the user adds to an authenticator app, and
 * {@link #confirm} proves they can produce a code before sign-in starts asking for one. Confirming hands
 * out recovery codes once; each works a single time. The secret is sealed with the password pepper, so the
 * database alone cannot mint codes, and a TOTP step is accepted at most once, so a code cannot be replayed.
 *
 * <p>Sign-in with a second factor is also two steps. The password check returns a challenge
 * ({@link #challenge}): the user id, an expiry and a nonce under an HMAC keyed by the pepper, so it is
 * stateless, survives a restart and works across replicas. The second step ({@link #verifyCode}) is only
 * reached with a valid challenge, and a wrong code counts as a failed sign-in for the lockout.
 */
@Service
@Slf4j
public class MfaService {

    public static final String ISSUER = "CertPing";
    public static final int RECOVERY_CODES = 8;
    static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    private final UserMfaRepository userMfaRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthAuditRecorder authAuditRecorder;
    private final AccessAuditRecorder accessAuditRecorder;
    private final Clock clock;

    public MfaService(UserMfaRepository userMfaRepository, UserRepository userRepository,
                      PasswordEncoder passwordEncoder, AuthAuditRecorder authAuditRecorder,
                      AccessAuditRecorder accessAuditRecorder, Clock clock) {
        this.userMfaRepository = userMfaRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authAuditRecorder = authAuditRecorder;
        this.accessAuditRecorder = accessAuditRecorder;
        this.clock = clock;
    }

    /** What the account page shows. */
    public record Status(boolean enabled, OffsetDateTime confirmedAt, int recoveryCodesRemaining) {
    }

    /** What the authenticator app is given; the secret is shown once, during enrollment. */
    public record Enrollment(String secret, String otpauthUri) {
    }

    @Transactional(readOnly = true)
    public Status status(Integer userId) {
        return userMfaRepository.findById(userId)
                .filter(UserMfa::isConfirmed)
                .map(m -> new Status(true, m.getConfirmedAt(), recoveryHashes(m).size()))
                .orElse(new Status(false, null, 0));
    }

    /** Whether sign-in must ask {@code userId} for a code. */
    @Transactional(readOnly = true)
    public boolean isEnabled(Integer userId) {
        return userMfaRepository.isEnabled(userId);
    }

    /**
     * Starts (or restarts) enrollment with a fresh secret. Refused while a confirmed factor exists: turn
     * it off first, with the password, so a session alone cannot swap the authenticator.
     */
    @Transactional
    public Enrollment enroll(Integer userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        Optional<UserMfa> existing = userMfaRepository.findById(userId);
        if (existing.isPresent() && existing.get().isConfirmed()) {
            throw new ConflictException("Two-factor authentication is already on. Turn it off before enrolling again.");
        }
        byte[] secret = Totp.newSecret();
        UserMfa row = existing.orElseGet(() -> UserMfa.builder().userId(userId).build());
        row.setSecretSealed(sealer().seal(secret));
        row.setConfirmedAt(null);
        row.setLastUsedStep(null);
        row.setRecoveryCodeHashes("");
        userMfaRepository.save(row);
        String accountName = user.getEmail() != null ? user.getEmail() : user.getUsername();
        return new Enrollment(Totp.base32(secret), Totp.otpauthUri(ISSUER, accountName, secret));
    }

    /** Confirms the pending enrollment with a code from the app and returns the recovery codes, once. */
    @Transactional
    public List<String> confirm(Integer userId, String code) {
        UserMfa row = userMfaRepository.findById(userId)
                .orElseThrow(() -> new BadRequestException("Start enrollment first"));
        if (row.isConfirmed()) {
            throw new ConflictException("Two-factor authentication is already on.");
        }
        byte[] secret = sealer().open(row.getSecretSealed());
        Long step = Totp.matchingStep(secret, code, clock.instant().getEpochSecond(), null);
        if (step == null) {
            throw new BadRequestException("That code was not valid. Check the time on your device and try again.");
        }
        List<String> recoveryCodes = newRecoveryCodes();
        row.setConfirmedAt(OffsetDateTime.now(clock).withOffsetSameInstant(ZoneOffset.UTC));
        row.setLastUsedStep(step);
        row.setRecoveryCodeHashes(recoveryCodes.stream().map(MfaService::sha256).collect(Collectors.joining(",")));
        userMfaRepository.save(row);
        authAuditRecorder.mfaEnabled(account(userId));
        log.info("Two-factor authentication enabled for user {}", userId);
        return recoveryCodes;
    }

    /** Turns the factor off; takes the account's password, as the session may have been left open. */
    @Transactional
    public void disable(Integer userId, String password) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        if (user.getPasswordHash() == null || !passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new UnauthorizedException("The password was incorrect");
        }
        UserMfa row = userMfaRepository.findById(userId).orElse(null);
        if (row == null) {
            return;
        }
        boolean wasOn = row.isConfirmed();
        userMfaRepository.delete(row);
        if (wasOn) {
            authAuditRecorder.mfaDisabled(SignInAccount.of(user));
            log.info("Two-factor authentication disabled for user {}", userId);
        }
    }

    /**
     * Removes {@code userId}'s factor without a password: for an administrator helping a member who lost
     * both the app and the recovery codes. The caller checks the permission; the row is audited as
     * {@code member.mfa_reset} by the administrator.
     */
    @Transactional
    public boolean reset(User member) {
        UserMfa row = userMfaRepository.findById(member.getId()).orElse(null);
        if (row == null) {
            return false;
        }
        userMfaRepository.delete(row);
        accessAuditRecorder.memberMfaReset(member);
        log.info("Two-factor authentication reset for user {}", member.getId());
        return true;
    }

    /**
     * Checks a sign-in code: a TOTP code for a step not yet used, or an unused recovery code. Records the
     * step or spends the recovery code, so neither can be used again.
     */
    @Transactional
    public boolean verifyCode(Integer userId, String code) {
        UserMfa row = userMfaRepository.findById(userId).filter(UserMfa::isConfirmed).orElse(null);
        if (row == null || code == null) {
            return false;
        }
        byte[] secret = sealer().open(row.getSecretSealed());
        Long step = Totp.matchingStep(secret, code, clock.instant().getEpochSecond(), row.getLastUsedStep());
        if (step != null) {
            row.setLastUsedStep(step);
            userMfaRepository.save(row);
            return true;
        }
        String given = sha256(normalizeRecovery(code));
        List<String> hashes = new ArrayList<>(recoveryHashes(row));
        boolean spent = false;
        for (int i = 0; i < hashes.size(); i++) {
            if (MessageDigest.isEqual(hashes.get(i).getBytes(StandardCharsets.US_ASCII),
                    given.getBytes(StandardCharsets.US_ASCII))) {
                hashes.remove(i);
                spent = true;
                break;
            }
        }
        if (!spent) {
            return false;
        }
        row.setRecoveryCodeHashes(String.join(",", hashes));
        userMfaRepository.save(row);
        log.info("Recovery code used for user {}; {} remain", userId, hashes.size());
        return true;
    }

    // ── Challenge tokens ────────────────────────────────────────────────────────────────────────

    /** A challenge for {@code userId}, good for {@link #CHALLENGE_TTL}. */
    public String challenge(Integer userId) {
        byte[] nonce = new byte[16];
        RANDOM.nextBytes(nonce);
        long expires = clock.instant().plus(CHALLENGE_TTL).getEpochSecond();
        String payload = userId + ":" + expires + ":" + B64.encodeToString(nonce);
        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        return B64.encodeToString(payloadBytes) + "." + B64.encodeToString(sealer().hmac(payloadBytes));
    }

    /** The user a challenge was issued for, when it is intact and not yet expired. */
    public Optional<Integer> verifyChallenge(String token) {
        if (token == null) {
            return Optional.empty();
        }
        int dot = token.indexOf('.');
        if (dot <= 0 || dot == token.length() - 1) {
            return Optional.empty();
        }
        try {
            byte[] payloadBytes = B64D.decode(token.substring(0, dot));
            byte[] signature = B64D.decode(token.substring(dot + 1));
            if (!MessageDigest.isEqual(sealer().hmac(payloadBytes), signature)) {
                return Optional.empty();
            }
            String[] parts = new String(payloadBytes, StandardCharsets.UTF_8).split(":");
            if (parts.length != 3) {
                return Optional.empty();
            }
            long expires = Long.parseLong(parts[1]);
            if (clock.instant().getEpochSecond() > expires) {
                return Optional.empty();
            }
            return Optional.of(Integer.parseInt(parts[0]));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────────────────────

    private PepperedPasswordEncoder sealer() {
        if (passwordEncoder instanceof PepperedPasswordEncoder peppered) {
            return peppered;
        }
        throw new IllegalStateException("Two-factor authentication needs the peppered password encoder");
    }

    private SignInAccount account(Integer userId) {
        return userRepository.findById(userId).map(SignInAccount::of)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    private static List<String> recoveryHashes(UserMfa row) {
        String stored = row.getRecoveryCodeHashes();
        if (stored == null || stored.isBlank()) {
            return List.of();
        }
        return Arrays.stream(stored.split(",")).filter(s -> !s.isBlank()).toList();
    }

    /** Ten Base32 characters, shown as {@code xxxxx-xxxxx}: 50 bits, enough for a code that works once. */
    static List<String> newRecoveryCodes() {
        List<String> codes = new ArrayList<>(RECOVERY_CODES);
        for (int i = 0; i < RECOVERY_CODES; i++) {
            byte[] raw = new byte[7];
            RANDOM.nextBytes(raw);
            String base32 = Totp.base32(raw).substring(0, 10).toLowerCase(Locale.ROOT);
            codes.add(base32.substring(0, 5) + "-" + base32.substring(5));
        }
        return codes;
    }

    static String normalizeRecovery(String code) {
        return code.replace("-", "").replace(" ", "").trim().toLowerCase(Locale.ROOT);
    }

    static String sha256(String code) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(normalizeRecovery(code).getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }
}
