// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.iot.service.IotDeviceEventService;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import tools.jackson.core.JacksonException;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Deterministic, idempotent re-correlation of certificates whose device was not synchronized yet
 * at issuance time. Runs after each successful device sync of a source and repeats the exact same
 * source-scoped lookup ingestion performed — never a looser one — so a re-link can only ever
 * produce the link the original enrollment would have made.
 *
 * <p>Profile reconciliation is a separate path: {@code IotCertificateProfileCorrelationService}
 * resolves it from Intune's {@code managedDeviceCertificateState} reporting during a
 * certificate-profile sync. A certificate issued against a profile that has not been synced yet
 * stays {@code PENDING_SYNC} until that sync runs.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IotCertificateCorrelationService {

    /**
     * How many of each orphaned device's <b>dead</b> links one page repairs, newest first.
     *
     * <p>Usable links are never capped. Repair is one-shot, so a skipped usable link strands a
     * live credential for good, and there is no safe assumption about how many certificates a
     * device carries — an organization decides that by how many SCEP profiles it pushes. Capping
     * the expired and revoked tail is what keeps one long-renewing device from flooding the page,
     * and losing the oldest of those costs nothing.
     */
    static final int MAX_REPAIRED_DEAD_LINKS_PER_DEVICE = 10;

    private final IotCertificateEnrollmentRepository enrollmentRepository;
    private final IotDeviceCertificateRepository certificateRepository;
    private final IotDeviceRepository deviceRepository;
    private final IotDeviceEventService eventService;
    private final ObjectMapper objectMapper;
    private final IotCertificateSupersessionService supersessionService;

    /**
     * Links enrollments (and their certificates) whose Microsoft-validated identifier now matches
     * a device in this source. Bounded per run; the next sync completes the tail. Called inside
     * the sync-completion transaction.
     */
    public void relinkDevicesForSource(IotDeviceSource source, OffsetDateTime occurredAt,
                                       String correlationId, boolean staleDevicesRetired) {
        // Only rows whose device exists now come back, so the per-row work below is proportional
        // to the links actually made, not to the size of the pending backlog.
        List<IotCertificateEnrollment> relinkable =
                enrollmentRepository.findRelinkableByDeviceSourceId(
                        source.getId(), staleDevicesRetired);
        int linked = 0;
        // Collected rather than reconciled per row: several certificates of one device commonly
        // relink in the same pass, and the question is per group, not per certificate.
        Set<CertificateGroup> completedGroups = new LinkedHashSet<>();
        for (IotCertificateEnrollment enrollment : relinkable) {
            if (relink(source, enrollment, occurredAt, correlationId, completedGroups)) {
                linked++;
            }
        }
        int candidateCount = relinkable.size();
        if (candidateCount > 0) {
            log.info("Certificate device re-link after sync: sourceId={} linked={} of {} candidates",
                    source.getId(), linked, candidateCount);
        }
        linkRenewalsAwaitingTheirPriorDevice(source, occurredAt, correlationId, completedGroups);
        reconcileSupersession(completedGroups, correlationId);
    }

    /**
     * Asks the supersession rules to re-examine every group a link completed. Deferred to the end
     * of the pass so it takes no locks that later steps would have to order around.
     */
    private void reconcileSupersession(Set<CertificateGroup> groups, String correlationId) {
        for (CertificateGroup group : groups) {
            supersessionService.reconcileGroup(
                    group.organizationId(), group.deviceId(), group.profileId(), correlationId);
        }
    }

    /** A device-and-profile pair whose certificates may now supersede one another. */
    private record CertificateGroup(Long organizationId, Long deviceId, Long profileId) {
        static void collect(Set<CertificateGroup> groups, IotDeviceCertificate certificate) {
            if (certificate.getDeviceId() != null && certificate.getProfileId() != null) {
                groups.add(new CertificateGroup(certificate.getOrganizationId(),
                        certificate.getDeviceId(), certificate.getProfileId()));
            }
        }
    }

    /**
     * Gives a device to renewals that inherited none because the certificate they renewed had none
     * yet.
     *
     * <p>A renewal asserts no identifier of its own — the schema forbids it — so it takes its
     * device from the exact prior certificate and nothing re-resolves it afterwards. A certificate
     * issued before its device had synced therefore poisons its whole renewal chain: each renewal
     * inherits null, and the live credential of a device that renews on a short cycle stays
     * unattributable while its expired predecessor is the one still reported as current. Runs
     * after the identifier re-link above, so a predecessor linked in this same pass is already
     * visible here.
     */
    private void linkRenewalsAwaitingTheirPriorDevice(
            IotDeviceSource source, OffsetDateTime occurredAt, String correlationId,
            Set<CertificateGroup> completedGroups) {
        List<IotCertificateEnrollment> renewals = enrollmentRepository
                .findRenewalsAwaitingTheirPriorDevice(source.getId());
        int linked = 0;
        for (IotCertificateEnrollment renewal : renewals) {
            List<Long> deviceIds = certificateRepository.findBySourceScopedIssuerAndSerial(
                            renewal.getOrganizationId(), source.getId(),
                            renewal.getPriorCertificateIssuerDn(),
                            renewal.getPriorCertificateSerialNumber())
                    .stream().map(IotDeviceCertificate::getDeviceId)
                    .filter(java.util.Objects::nonNull).distinct().toList();
            if (deviceIds.size() != 1) {
                // Two predecessors answering to one issuer and serial is not a thing to guess at.
                log.debug("Renewal left unlinked, its predecessor is not unique: sourceId={} "
                                + "enrollment={} candidates={} correlation={}",
                        source.getId(), renewal.getEnrollmentXref(), deviceIds.size(),
                        correlationId);
                continue;
            }
            Long deviceId = deviceIds.getFirst();
            renewal.setDeviceId(deviceId);
            // A row stamped RENEWAL_SOURCE_NOT_FOUND has now found its source, so it stops
            // claiming otherwise. The check constraint allows both values for a renewal.
            renewal.setDeviceMatchStatus(IotCertificateDeviceLinkService.INHERITED_FROM_RENEWAL);
            renewal.setUpdatedAt(occurredAt);
            enrollmentRepository.save(renewal);
            certificateRepository.findByEnrollmentId(renewal.getId()).ifPresent(certificate -> {
                certificate.setDeviceId(deviceId);
                certificate.setUpdatedAt(occurredAt);
                certificateRepository.save(certificate);
                CertificateGroup.collect(completedGroups, certificate);
            });
            // The device may have been archived while this renewal was unattributed, which is
            // exactly why it was archivable: nothing usable appeared to be issued against it.
            // A device holding a live credential cannot stay hidden.
            if (deviceRepository.restoreArchivedDevice(deviceId) == 1) {
                log.info("Archived device returned to the inventory by a linked renewal: "
                                + "sourceId={} enrollment={} deviceId={} correlation={}",
                        source.getId(), renewal.getEnrollmentXref(), deviceId, correlationId);
            }
            eventService.recordEnrollment(renewal, DeviceEventType.CERTIFICATE_DEVICE_MATCHED,
                    IotCertificateDeviceLinkService.INHERITED_FROM_RENEWAL,
                    "Renewal linked to the device its predecessor was later matched to",
                    Map.of("priorCertificateSerialNumber",
                            renewal.getPriorCertificateSerialNumber()),
                    correlationId,
                    "scep-renewal-device-inherited:" + renewal.getEnrollmentXref(), occurredAt);
            linked++;
        }
        if (!renewals.isEmpty()) {
            log.info("Renewal device inheritance after sync: sourceId={} linked={} of {} "
                    + "correlation={}", source.getId(), linked, renewals.size(), correlationId);
        }
    }

    /**
     * Moves certificate links off the exact bounded device page the caller just orphaned.
     *
     * <p>The repair key is the orphaned row's own Entra device id, never the identifier the
     * enrollment asserted. Intune mints a fresh {@code managedDeviceId} when a device re-enrolls,
     * so the provider id cannot survive the event, and {@code uk_iot_device_source_id} already
     * guarantees no second row in the source can carry it. The Entra device object is what stays
     * constant across a re-enrollment, so it is the only identity that can prove a replacement row
     * is the same physical device. That makes one rule enough for both an initial enrollment and a
     * renewal that inherited its device, which is why a true renewal needs no asserted identifier
     * of its own. Exactly one registered replacement may answer; zero or several keeps the
     * historical link, because a certificate on a stale device is recoverable and one on the wrong
     * device is not.
     *
     * <p>The caller owns the transaction and the write locks on {@code orphanedDevices}, which
     * closes both message orderings for an <b>initial</b> enrollment: it either commits its link
     * first and is repaired here, or blocks on the device row and then sees only the replacement.
     *
     * <p>A true renewal is not covered by that argument, because
     * {@code IotCertificateDeviceLinkService.resolveRenewal} copies the device from the prior
     * certificate and never reads {@code iot_device}, so it takes no device lock to block on. A
     * renewal landing in the same instant can still write a link to the row being orphaned, and
     * <b>nothing revisits it</b>: repair only ever runs on rows a sync has just moved out of
     * REGISTERED, so an already-orphaned row is never selected again. Such a link stays on the
     * orphaned row until something else moves it. It is still never linked to the <i>wrong</i>
     * device — the row it points at is the device it was issued against — but "the next sync will
     * fix it" is not true and must not be relied on.
     *
     * <p>Locks are taken devices-first, enrollments-second, matching the order
     * {@code IotCertificateIngestionService} uses on the issuance side. Reversing either would
     * deadlock the two paths against each other.
     */
    public int relinkFromOrphanedDevices(
            Long sourceId, OffsetDateTime syncStartedAt, List<IotDevice> orphanedDevices,
            OffsetDateTime occurredAt, String correlationId) {
        Map<Long, OrphanedIdentity> repairableById = new LinkedHashMap<>();
        for (IotDevice orphanedDevice : orphanedDevices) {
            String entraDeviceId = entraDeviceId(orphanedDevice);
            if (entraDeviceId != null) {
                repairableById.put(orphanedDevice.getId(),
                        new OrphanedIdentity(orphanedDevice, entraDeviceId));
            }
        }
        int skippedWithoutIdentity = orphanedDevices.size() - repairableById.size();
        if (repairableById.isEmpty()) {
            logSkippedWithoutIdentity(sourceId, skippedWithoutIdentity, correlationId);
            return 0;
        }
        // Devices before enrollments, always: the issuance path locks in the same order.
        Map<String, List<IotDevice>> replacementsByEntraDeviceId = replacementsByEntraDeviceId(
                sourceId, syncStartedAt, repairableById.values().stream()
                        .map(OrphanedIdentity::entraDeviceId).distinct().toList());
        List<Long> repairableLinkIds = enrollmentRepository.findRepairableLinkIds(
                List.copyOf(repairableById.keySet()), occurredAt,
                MAX_REPAIRED_DEAD_LINKS_PER_DEVICE);
        logSkippedWithoutIdentity(sourceId, skippedWithoutIdentity, correlationId);
        if (repairableLinkIds.isEmpty()) {
            return 0;
        }
        List<IotCertificateEnrollment> enrollments =
                enrollmentRepository.lockLinksForRepair(repairableLinkIds);

        // Locked in key order: these rows are about to be updated, and the check-in path locks the
        // same rows the same way. Leaving it to the flush would make the order accidental.
        Map<Long, IotDeviceCertificate> certificatesByEnrollmentId = certificateRepository
                .lockByEnrollmentIdIn(enrollments.stream()
                        .map(IotCertificateEnrollment::getId).toList())
                .stream().collect(Collectors.toMap(
                        IotDeviceCertificate::getEnrollmentId, Function.identity()));

        List<IotCertificateEnrollment> reboundEnrollments = new ArrayList<>();
        List<IotDeviceCertificate> reboundCertificates = new ArrayList<>();
        int kept = 0;
        for (IotCertificateEnrollment enrollment : enrollments) {
            OrphanedIdentity orphaned = repairableById.get(enrollment.getDeviceId());
            List<IotDevice> replacements = replacementsByEntraDeviceId
                    .getOrDefault(orphaned.entraDeviceId(), List.of());
            if (replacements.size() != 1) {
                // Zero is the ordinary case for a device that was genuinely retired, so this is
                // per-link detail rather than news; the batch summary carries the counts.
                kept++;
                log.debug("Certificate link kept on the orphaned device: sourceId={} enrollment={} "
                                + "oldDevice={} registeredReplacements={} correlation={}",
                        sourceId, enrollment.getEnrollmentXref(),
                        orphaned.device().getDeviceXref(), replacements.size(), correlationId);
                continue;
            }
            IotDevice replacement = replacements.getFirst();
            // Recorded before the move, so the event lands on the orphaned device's timeline. That
            // is where someone asking "where did this device's certificates go" is looking; the
            // detail carries the destination, and the enrollment feed shows it from both ends.
            recordRebind(enrollment, orphaned.device(), replacement, correlationId, occurredAt);
            enrollment.setDeviceId(replacement.getId());
            enrollment.setUpdatedAt(occurredAt);
            reboundEnrollments.add(enrollment);
            IotDeviceCertificate certificate = certificatesByEnrollmentId.get(enrollment.getId());
            if (certificate != null) {
                certificate.setDeviceId(replacement.getId());
                certificate.setUpdatedAt(occurredAt);
                reboundCertificates.add(certificate);
            }
            // Per certificate: a mass re-enrollment moves tens of thousands. The batch summary
            // carries the counts and the audit event carries the per-certificate record.
            log.debug("Certificate moved to the re-enrolled device: sourceId={} enrollment={} "
                            + "certificate={} oldDevice={} newDevice={} correlation={}",
                    sourceId, enrollment.getEnrollmentXref(),
                    certificate == null ? null : certificate.getCertificateXref(),
                    orphaned.device().getDeviceXref(), replacement.getDeviceXref(), correlationId);
        }
        enrollmentRepository.saveAll(reboundEnrollments);
        certificateRepository.saveAll(reboundCertificates);
        // A certificate moved onto the replacement joins whatever that device already holds, so a
        // predecessor there may now be superseded. Last step of the pass: it takes locks of its own.
        Set<CertificateGroup> reboundGroups = new LinkedHashSet<>();
        reboundCertificates.forEach(certificate ->
                CertificateGroup.collect(reboundGroups, certificate));
        reconcileSupersession(reboundGroups, correlationId);
        if (kept > 0) {
            log.info("Certificate links kept on orphaned devices: sourceId={} kept={} "
                    + "correlation={}", sourceId, kept, correlationId);
        }
        return reboundEnrollments.size();
    }

    /**
     * A device with no Entra identity has nothing stable to match a replacement on, so its links
     * stay put. Reported because it is silent otherwise, and it is the one class of certificate
     * this repair can never move.
     */
    private void logSkippedWithoutIdentity(Long sourceId, int skipped, String correlationId) {
        if (skipped > 0) {
            log.info("Orphaned devices without an Entra identity keep their certificate links: "
                    + "sourceId={} devices={} correlation={}", sourceId, skipped, correlationId);
        }
    }

    private Map<String, List<IotDevice>> replacementsByEntraDeviceId(
            Long sourceId, OffsetDateTime syncStartedAt, List<String> entraDeviceIds) {
        Map<String, List<IotDevice>> replacements = new LinkedHashMap<>();
        for (IotDevice device : deviceRepository.findRegisteredByEntraDeviceIds(
                sourceId, syncStartedAt, entraDeviceIds)) {
            String entraDeviceId = entraDeviceId(device);
            if (entraDeviceId != null) {
                replacements.computeIfAbsent(entraDeviceId, key -> new ArrayList<>()).add(device);
            }
        }
        return replacements;
    }

    /** The source-scoped Entra device identity Intune reported for the row, or null. */
    private String entraDeviceId(IotDevice device) {
        String identifiers = device.getSourceIdentifiersJson();
        if (identifiers == null || identifiers.isBlank()) {
            return null;
        }
        try {
            // Must agree with the `->> 'entraDeviceId'` the replacement query matches on, or a row
            // PostgreSQL selected would be dropped here and change the uniqueness decision.
            // `->>` renders any scalar as text and yields NULL only for a missing or JSON-null
            // key, which is what asText() on a non-container node does.
            JsonNode entraDeviceId = objectMapper.readTree(identifiers).path("entraDeviceId");
            if (entraDeviceId.isMissingNode() || entraDeviceId.isNull()
                    || entraDeviceId.isContainer()) {
                return null;
            }
            String value = entraDeviceId.asString();
            return value.isBlank() ? null : value;
        } catch (JacksonException exception) {
            log.warn("Ignoring malformed device identifiers during certificate rebind: device={}",
                    device.getDeviceXref());
            return null;
        }
    }

    private void recordRebind(
            IotCertificateEnrollment enrollment, IotDevice oldDevice, IotDevice newDevice,
            String correlationId, OffsetDateTime occurredAt) {
        eventService.recordEnrollment(enrollment, DeviceEventType.CERTIFICATE_DEVICE_MATCHED,
                "REBOUND", "Certificate moved to the active re-enrolled device",
                Map.of("oldDeviceXref", oldDevice.getDeviceXref(),
                        "newDeviceXref", newDevice.getDeviceXref(),
                        "reason", "linked device became orphaned after certificate issuance"),
                correlationId,
                // Keyed on the destination too: a device re-enrolled twice is rebound twice, and
                // an enrollment-only key would silently drop the audit record for the second move.
                "scep-device-orphan-reconcile:" + enrollment.getEnrollmentXref()
                        + ":" + newDevice.getDeviceXref(), occurredAt);
    }

    /** An orphaned row paired with the identity a replacement row must carry to inherit its links. */
    private record OrphanedIdentity(IotDevice device, String entraDeviceId) {
    }

    private boolean relink(IotDeviceSource source, IotCertificateEnrollment enrollment,
                           OffsetDateTime occurredAt, String correlationId,
                           Set<CertificateGroup> completedGroups) {
        // DEVICE_NOT_SYNCED is only ever written for a Microsoft-validated identifier, but re-check
        // instead of assuming: linking is the one operation that must never be sloppy.
        String identifierType = enrollment.getSourceIdentifierType();
        boolean resolvableType =
                IotCertificateDeviceLinkService.TYPE_MANAGED_DEVICE_ID.equals(identifierType)
                        || IotCertificateDeviceLinkService.TYPE_UNKNOWN.equals(identifierType);
        if (!IotCertificateDeviceLinkService.ASSURANCE_MICROSOFT_VALIDATED
                .equals(enrollment.getSourceIdentifierAssurance())
                || !resolvableType
                || enrollment.getAssertedSourceDeviceId() == null) {
            return false;
        }
        // Mirror ingestion's dispatch exactly. Widening the lookup for a MANAGED_DEVICE_ID row
        // would let a re-link make a match ingestion itself would never have made.
        List<IotDevice> matches = resolveActiveMatches(source, enrollment);
        if (matches.size() > 1) {
            if (IotCertificateDeviceLinkService.AMBIGUOUS
                    .equals(enrollment.getDeviceMatchStatus())) {
                // Already recorded, and still ambiguous. Rewriting it every sync would churn
                // updated_at for no change.
                return false;
            }
            // Recorded, and no longer terminal: the row is re-examined after any sync that
            // retires stale devices, so an ambiguity that existed only because a duplicate row
            // had not been orphaned yet resolves on its own.
            //
            // Recorded even on a partial sync, deliberately. Leaving it DEVICE_NOT_SYNCED would
            // keep it in the half of the window reserved for rows still waiting for their device,
            // which is taken oldest-first — a tenant whose syncs are usually partial would fill
            // that half with rows that cannot resolve and shut out the ones that can.
            enrollment.setDeviceMatchStatus(IotCertificateDeviceLinkService.AMBIGUOUS);
            enrollment.setUpdatedAt(occurredAt);
            enrollmentRepository.save(enrollment);
            eventService.recordEnrollment(enrollment, DeviceEventType.CERTIFICATE_DEVICE_UNMATCHED,
                    IotCertificateDeviceLinkService.AMBIGUOUS,
                    "Validated device identifier matches more than one device in this source",
                    Map.of("identifierValue", enrollment.getAssertedSourceDeviceId()),
                    correlationId,
                    "scep-device-ambiguous:" + enrollment.getEnrollmentXref(), occurredAt);
            return false;
        }
        if (matches.isEmpty()) {
            return false;
        }
        IotDevice device = matches.get(0);
        enrollment.setDeviceId(device.getId());
        enrollment.setDeviceMatchStatus(IotCertificateDeviceLinkService.MATCHED);
        enrollment.setUpdatedAt(occurredAt);
        enrollmentRepository.save(enrollment);
        certificateRepository.findByEnrollmentId(enrollment.getId()).ifPresent(certificate -> {
            certificate.setDeviceId(device.getId());
            certificate.setUpdatedAt(occurredAt);
            certificateRepository.save(certificate);
            CertificateGroup.collect(completedGroups, certificate);
        });
        eventService.recordEnrollment(enrollment, DeviceEventType.CERTIFICATE_DEVICE_MATCHED,
                IotCertificateDeviceLinkService.MATCHED,
                "Certificate re-linked to its device after device sync",
                Map.of("identifierValue", enrollment.getAssertedSourceDeviceId(),
                        "identifierType", enrollment.getSourceIdentifierType()),
                correlationId,
                "scep-device-relink:" + enrollment.getEnrollmentXref(), occurredAt);
        return true;
    }

    private List<IotDevice> resolveActiveMatches(
            IotDeviceSource source, IotCertificateEnrollment enrollment) {
        return IotCertificateDeviceLinkService.TYPE_MANAGED_DEVICE_ID.equals(
                enrollment.getSourceIdentifierType())
                ? deviceRepository.findRegisteredBySourceDeviceId(
                        source.getId(), enrollment.getAssertedSourceDeviceId())
                        .map(List::of).orElseGet(List::of)
                : deviceRepository.findRegisteredBySourceScopedIdentifier(
                        source.getId(), enrollment.getAssertedSourceDeviceId());
    }
}
