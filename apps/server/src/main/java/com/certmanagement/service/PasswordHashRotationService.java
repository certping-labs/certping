// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.entity.User;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.PepperedPasswordEncoder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Drives transparent pepper rotation for {@code users.password_hash}.
 *
 * <p>The encoder's {@link PepperedPasswordEncoder#reEncrypt(String)} decrypts a
 * stored hash with its embedded pepper version and re-encrypts it under the
 * currently active version, without needing the user's password. This service
 * finds rows on non-active versions and pushes each through {@code reEncrypt}.
 *
 * <p><b>Failure semantics:</b>
 * <ul>
 *   <li><b>Per-row failure</b> (e.g. malformed ciphertext, pepper version key
 *       no longer in the map, GCM tag mismatch): the row is logged and counted
 *       as {@code skipped}. The batch continues with the next row.
 *   <li><b>Per-batch / infrastructure failure</b> (e.g. DB connection lost
 *       during {@code saveAll}): the batch's transaction rolls back atomically
 *       (no partial writes), the exception propagates up, and the rotation
 *       aborts. Safe to re-run because committed batches stayed committed.
 *   <li><b>Stall guard</b>: if a full batch processes {@code batchSize} rows
 *       but the count of remaining rows on the source version did not decrease
 *       (e.g. every row in the batch was skipped), the drain stops with a
 *       warning to avoid an infinite loop.
 * </ul>
 *
 * <p><b>Typical rotation runbook</b> (see {@code docs/self-hosting.md}):
 * <ol>
 *   <li>Set the new pepper (e.g. {@code PASSWORD_PEPPER_V2}) and make it active with
 *       {@code PASSWORD_PEPPER_ACTIVE_VERSION=v2}. Restart.
 *   <li>{@link #inventory()} to confirm both versions are configured.
 *   <li>{@link #rotateAllToActive(int)} drains every non-active version's rows
 *       onto the active version.
 *   <li>Confirm inventory shows zero rows on the old version, then remove the
 *       old {@code PASSWORD_PEPPER_V*} and restart.
 * </ol>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordHashRotationService {

    /** Rows per batch at most: each batch is one transaction over the users table. */
    static final int MAX_BATCH_SIZE = 1000;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /** Optional (setter-injected): the TOTP secrets sealed under the pepper, re-sealed with the hashes. */
    private com.certmanagement.repository.UserMfaRepository userMfaRepository;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setUserMfaRepository(com.certmanagement.repository.UserMfaRepository userMfaRepository) {
        this.userMfaRepository = userMfaRepository;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Response types — typed records so Spring serializes them as clean JSON
    // and Postman / OpenAPI consumers see explicit field names.
    // ─────────────────────────────────────────────────────────────────────────

    /** Counts of password_hash rows per pepper version, plus the currently active version. */
    public record InventoryReport(String activeVersion, Map<String, Long> counts) {}

    /** Result of a single batch: migrated successfully + skipped due to per-row errors. */
    public record BatchSummary(int migrated, int skipped) {}

    /** Aggregate report from rotateAllToActive: totals + per-source-version counts + post-state. */
    public record RotationReport(
            String activeVersion,
            int migrated,
            int skipped,
            Map<String, Integer> byVersion,
            Map<String, Long> inventoryAfter) {}

    // ─────────────────────────────────────────────────────────────────────────
    // Public API
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns the currently-active pepper version and a count of rows per
     * configured pepper version. Use to confirm rotation progress and to verify
     * a version is safe to retire (count == 0) before removing it.
     */
    public InventoryReport inventory() {
        PepperedPasswordEncoder encoder = requireEncoder();
        return new InventoryReport(encoder.activeVersion(), rawCounts(encoder));
    }

    /**
     * Drains every row whose embedded pepper version is NOT the currently
     * active version onto the active version. Iterates each non-active version
     * to completion (or stall) before moving to the next. Each batch is its own
     * transaction; the rotation is safe to interrupt and resume.
     *
     * @param batchSize rows per batch / per transaction, 1 to {@value #MAX_BATCH_SIZE}.
     * @return aggregate report across all versions touched.
     */
    public RotationReport rotateAllToActive(int batchSize) {
        if (batchSize < 1 || batchSize > MAX_BATCH_SIZE) {
            throw new IllegalArgumentException("batchSize must be between 1 and " + MAX_BATCH_SIZE);
        }
        PepperedPasswordEncoder encoder = requireEncoder();
        String active = encoder.activeVersion();
        int totalMigrated = 0;
        int totalSkipped = 0;
        Map<String, Integer> byVersion = new LinkedHashMap<>();

        for (String version : encoder.configuredVersions()) {
            if (version.equals(active)) continue;
            BatchSummary versionResult = drainVersion(version, batchSize);
            if (versionResult.migrated() > 0 || versionResult.skipped() > 0) {
                byVersion.put(version, versionResult.migrated());
            }
            totalMigrated += versionResult.migrated();
            totalSkipped += versionResult.skipped();
        }

        int resealed = resealMfaSecrets(encoder);
        log.info("Pepper rotation complete: active={} migrated={} skipped={} mfaSecretsResealed={}",
                active, totalMigrated, totalSkipped, resealed);
        return new RotationReport(active, totalMigrated, totalSkipped, byVersion, rawCounts(encoder));
    }

    /**
     * Re-seals every TOTP secret ({@code user_mfa.secret_sealed}) not on the active version. The table
     * is small (one row per enrolled user), so one transaction covers it; a row that cannot be opened is
     * logged and left as it is, like a skipped password hash.
     */
    @Transactional
    int resealMfaSecrets(PepperedPasswordEncoder encoder) {
        if (userMfaRepository == null) {
            return 0;
        }
        int resealed = 0;
        for (com.certmanagement.entity.UserMfa row : userMfaRepository.findAll()) {
            if (!encoder.needsReEncrypt(row.getSecretSealed())) {
                continue;
            }
            try {
                row.setSecretSealed(encoder.seal(encoder.open(row.getSecretSealed())));
                userMfaRepository.save(row);
                resealed++;
            } catch (RuntimeException e) {
                log.error("Pepper migration skipped MFA secret for user id={}: {}", row.getUserId(), e.getMessage());
            }
        }
        return resealed;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal building blocks (package-private for tests)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Re-encrypts up to {@code batchSize} rows from {@code fromVersion} onto
     * the active pepper version in a single transaction.
     *
     * <p>Per-row failures are caught, logged, and counted as {@code skipped} —
     * the batch continues. Batch-level failures (DB issues) bubble as
     * exceptions and the {@code @Transactional} rollback discards any in-flight
     * row updates.
     */
    @Transactional
    BatchSummary migrateBatch(String fromVersion, int batchSize) {
        PepperedPasswordEncoder encoder = requireEncoder();
        if (fromVersion.equals(encoder.activeVersion())) {
            return new BatchSummary(0, 0);
        }
        String prefix = PepperedPasswordEncoder.ENC_V1_PREFIX + fromVersion + "$";
        List<User> rows = userRepository.findByPasswordHashStartingWith(
                prefix, PageRequest.of(0, batchSize));
        int migrated = 0;
        int skipped = 0;
        for (User u : rows) {
            try {
                u.setPasswordHash(encoder.reEncrypt(u.getPasswordHash()));
                migrated++;
            } catch (RuntimeException e) {
                skipped++;
                log.error("Pepper migration skipped user id={} version={}: {}",
                        u.getId(), fromVersion, e.getMessage());
            }
        }
        userRepository.saveAll(rows);
        log.info("Pepper migration batch: from={} to={} scanned={} migrated={} skipped={}",
                fromVersion, encoder.activeVersion(), rows.size(), migrated, skipped);
        return new BatchSummary(migrated, skipped);
    }

    /**
     * Drains one source version onto the active version, looping
     * {@link #migrateBatch} until either the source is empty or a stall is
     * detected (full batch but the source-version count didn't decrease — i.e.
     * every row in the batch was skipped, so further looping would never
     * make progress).
     */
    BatchSummary drainVersion(String fromVersion, int batchSize) {
        PepperedPasswordEncoder encoder = requireEncoder();
        if (fromVersion.equals(encoder.activeVersion())) {
            return new BatchSummary(0, 0);
        }
        String prefix = PepperedPasswordEncoder.ENC_V1_PREFIX + fromVersion + "$";
        int totalMigrated = 0;
        int totalSkipped = 0;
        long remaining = userRepository.countByPasswordHashStartingWith(prefix);

        while (remaining > 0) {
            BatchSummary batch = migrateBatch(fromVersion, batchSize);
            totalMigrated += batch.migrated();
            totalSkipped += batch.skipped();

            long newRemaining = userRepository.countByPasswordHashStartingWith(prefix);
            if (newRemaining >= remaining) {
                // Stall: the batch made no progress (all skipped, or concurrent
                // writes are creating rows faster than we drain). Stop instead
                // of looping forever. Operator must investigate the skip causes.
                log.warn("Pepper rotation stall: {} rows remain on '{}' but batch "
                        + "made no progress (migrated={} skipped={}). Aborting drain.",
                        newRemaining, fromVersion, batch.migrated(), batch.skipped());
                break;
            }
            remaining = newRemaining;
        }
        return new BatchSummary(totalMigrated, totalSkipped);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private Map<String, Long> rawCounts(PepperedPasswordEncoder encoder) {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (String version : encoder.configuredVersions()) {
            String prefix = PepperedPasswordEncoder.ENC_V1_PREFIX + version + "$";
            counts.put(version, userRepository.countByPasswordHashStartingWith(prefix));
        }
        return counts;
    }

    private PepperedPasswordEncoder requireEncoder() {
        if (!(passwordEncoder instanceof PepperedPasswordEncoder ppe)) {
            throw new IllegalStateException(
                    "PasswordEncoder bean is not PepperedPasswordEncoder; rotation cannot run.");
        }
        return ppe;
    }
}
