// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.repository;

import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.enums.ComplianceState;
import com.certmanagement.iot.enums.DeviceStatus;
import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface IotDeviceRepository extends JpaRepository<IotDevice, Long> {

    Optional<IotDevice> findByDeviceXrefAndOrganizationIdAndIsDeletedFalse(
            String deviceXref, Long organizationId);

    List<IotDevice> findAllByOrganizationIdAndIsDeletedFalseOrderById(
            Long organizationId, Pageable pageable);

    List<IotDevice> findAllByOrganizationIdAndDeviceXrefInAndIsDeletedFalse(
            Long organizationId, List<String> deviceXrefs);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT d FROM IotDevice d WHERE d.deviceXref = :deviceXref "
            + "AND d.organizationId = :organizationId AND d.isDeleted = false")
    Optional<IotDevice> lockByDeviceXrefAndOrganizationId(
            @Param("deviceXref") String deviceXref,
            @Param("organizationId") Long organizationId);

    @Lock(LockModeType.PESSIMISTIC_READ)
    @Query("SELECT d FROM IotDevice d WHERE d.deviceSourceId = :deviceSourceId "
            + "AND d.sourceDeviceId = :sourceDeviceId "
            + "AND d.status = com.certmanagement.iot.enums.DeviceStatus.REGISTERED "
            + "AND d.isDeleted = false")
    Optional<IotDevice> findRegisteredBySourceDeviceId(
            @Param("deviceSourceId") Long deviceSourceId,
            @Param("sourceDeviceId") String sourceDeviceId);

    /**
     * Resolves a validated identifier whose namespace the agent could not determine, by matching it
     * against every identifier namespace stored for the source: the provider's own device id and
     * the Entra device id kept in {@code source_identifiers_json}. Exact and source-scoped, never
     * fuzzy. Returns a list because the caller must refuse to link anything but a unique match —
     * two devices answering to one identifier is ambiguity, not a match.
     *
     * <p>Served by {@code idx_iot_device_source_entra_device_id}; the caller bounds the result.
     */
    @NativeQuery("""
            SELECT * FROM iot_device device
             WHERE device.device_source_id = :deviceSourceId
               AND device.is_deleted = false
               AND device.status = 'REGISTERED'
               AND (device.source_device_id = :identifier
                    OR device.source_identifiers_json ->> 'entraDeviceId' = :identifier)
             LIMIT 2
             FOR SHARE OF device
            """)
    List<IotDevice> findRegisteredBySourceScopedIdentifier(
            @Param("deviceSourceId") Long deviceSourceId,
            @Param("identifier") String identifier);

    /**
     * Registered rows carrying one of the given Entra device identities, for the bounded page of
     * certificate links a completed sync is repairing. The Entra device object survives an Intune
     * re-enrollment, so it is the only identity that can name the replacement row; the provider's
     * own device id cannot, since {@code uk_iot_device_source_id} makes it unique per source.
     *
     * <p>Served by {@code idx_iot_device_source_entra_device_id}. {@code FOR SHARE} holds the
     * replacements registered until the rebind commits, so a concurrent sync cannot orphan the row
     * a certificate is being moved onto.
     *
     * <p>{@code last_seen_in_source_at} must be at or after the sync that is doing the orphaning.
     * Stale rows are orphaned a page at a time in id order, so without this a second stale row
     * carrying the same Entra identity is still {@code REGISTERED} while an earlier page is being
     * repaired, and a certificate would be moved onto a row the very next page orphans.
     */
    @NativeQuery("""
            SELECT * FROM iot_device device
             WHERE device.device_source_id = :deviceSourceId
               AND device.is_deleted = false
               AND device.status = 'REGISTERED'
               AND device.last_seen_in_source_at >= :syncStartedAt
               AND device.source_identifiers_json ->> 'entraDeviceId' IN (:entraDeviceIds)
             ORDER BY device.id
             FOR SHARE OF device
            """)
    List<IotDevice> findRegisteredByEntraDeviceIds(
            @Param("deviceSourceId") Long deviceSourceId,
            @Param("syncStartedAt") OffsetDateTime syncStartedAt,
            @Param("entraDeviceIds") Collection<String> entraDeviceIds);

    List<IotDevice> findByDeviceSourceIdAndSourceDeviceIdInAndIsDeletedFalse(
            Long deviceSourceId, Collection<String> sourceDeviceIds);

    /**
     * The sync's page preload, archived rows included.
     *
     * <p>Native because {@code @Where(is_deleted = false)} hides archived rows from every entity
     * query, and here they must be visible: {@code uk_iot_device_source_id} still reserves the
     * source device id, so a source that reports an archived device again has to update that row
     * rather than insert a second one. Not seeing it turns a re-appearance into a unique-violation
     * that fails the whole page.
     */
    @NativeQuery("""
            SELECT * FROM iot_device device
             WHERE device.device_source_id = :deviceSourceId
               AND device.source_device_id IN (:sourceDeviceIds)
            """)
    List<IotDevice> findBySourceDeviceIdsIncludingArchived(
            @Param("deviceSourceId") Long deviceSourceId,
            @Param("sourceDeviceIds") Collection<String> sourceDeviceIds);

    /**
     * Returns an archived device to the inventory, and reports whether it had to.
     *
     * <p>Archiving only proves nothing was usable at that instant. A renewal inherits its device
     * from the prior certificate without reading {@code iot_device} at all, so a certificate can
     * still land on an archived row afterwards — and a live credential on a hidden device is
     * exactly what must not happen. Issuance calls this, so receiving a certificate is itself the
     * evidence that the device is still in use.
     *
     * <p>Guarded on {@code is_deleted} so the ordinary case updates no row.
     */
    @Modifying
    @NativeQuery("""
            UPDATE iot_device SET is_deleted = false
             WHERE id = :deviceId AND is_deleted = true
            """)
    int restoreArchivedDevice(@Param("deviceId") Long deviceId);

    /**
     * Reads one device, archived rows included.
     *
     * <p>Archiving has to stay reversible and inspectable, so the detail and activity views resolve
     * an archived device rather than reporting it missing — otherwise the only way back would be a
     * database edit. The inventory listing still hides it, which is the whole point of archiving.
     * Native because {@code @Where(is_deleted = false)} filters every entity query.
     */
    @NativeQuery("""
            SELECT * FROM iot_device device
             WHERE device.device_xref = :deviceXref
               AND device.organization_id = :organizationId
            """)
    Optional<IotDevice> findByDeviceXrefIncludingArchived(
            @Param("deviceXref") String deviceXref,
            @Param("organizationId") Long organizationId);

    /**
     * Reads one device by id, archived rows included, for resolving what a certificate belongs to.
     *
     * <p>A certificate keeps its device when that device is archived, so the read that renders it
     * has to see the row. Without this the summary comes back empty and the certificate reports as
     * unattributed — a different and much louder problem than "archived".
     */
    @NativeQuery("SELECT * FROM iot_device device WHERE device.id = :id")
    Optional<IotDevice> findByIdIncludingArchived(@Param("id") Long id);

    /** The same, for a page of certificates. Callers must skip the call on an empty list. */
    @NativeQuery("SELECT * FROM iot_device device WHERE device.id IN (:ids)")
    List<IotDevice> findAllByIdsIncludingArchived(@Param("ids") Collection<Long> ids);

    /**
     * Locks one device for archive; archived rows are visible here by design.
     *
     * <p>{@code FOR UPDATE} on purpose, and the only place in this class that uses it. Archiving
     * must decide whether anything usable is issued against the device, and a certificate being
     * inserted right now is invisible to that count until it commits. Inserting a certificate
     * takes {@code FOR KEY SHARE} on the device to check its foreign key, and {@code FOR UPDATE}
     * is the one mode that conflicts with it — so blocking that insert is exactly the mechanism
     * that makes the count trustworthy. The transaction acquires nothing else, so it cannot form
     * a cycle, and it holds the lock only for the length of one operator action on one device.
     */
    @NativeQuery("""
            SELECT * FROM iot_device device
             WHERE device.device_xref = :deviceXref
               AND device.organization_id = :organizationId
             FOR UPDATE OF device
            """)
    Optional<IotDevice> lockByDeviceXrefForArchive(
            @Param("deviceXref") String deviceXref,
            @Param("organizationId") Long organizationId);

    /**
     * Locks one device for restore. No invariant depends on what else is happening to the device,
     * so this takes the weaker mode that leaves foreign-key checks alone.
     */
    @NativeQuery("""
            SELECT * FROM iot_device device
             WHERE device.device_xref = :deviceXref
               AND device.organization_id = :organizationId
             FOR NO KEY UPDATE OF device
            """)
    Optional<IotDevice> lockByDeviceXrefForRestore(
            @Param("deviceXref") String deviceXref,
            @Param("organizationId") Long organizationId);

    /**
     * Inventory search. Every filter is optional; a null one is not applied.
     *
     * <p>The {@code CAST(... AS String)} around each text parameter is load-bearing, despite the
     * {@code IS NULL} guard that appears to make it unreachable. Postgres resolves function
     * signatures when it parses the statement, before any condition is evaluated: the driver sends
     * an untyped null, Postgres infers {@code bytea}, and the whole statement fails with
     * {@code function lower(bytea) does not exist} — even though the branch would never have run.
     * The cast is what tells the driver to bind text instead.
     *
     * <p>This broke the unfiltered listing, which is exactly what the UI requests first. Note that
     * H2 infers the type happily, so the repository tests pass either way; it only shows up against
     * Postgres. {@code DeploymentRepository} carries the same cast for
     * the same reason.
     */
    @Query("""
            SELECT d
            FROM IotDevice d
            LEFT JOIN IotDeviceEndpointPosture p ON p.deviceId = d.id
            LEFT JOIN IotDeviceOwner o ON o.deviceId = d.id AND o.isDeleted = false
            WHERE d.organizationId = :organizationId
              AND d.isDeleted = false
              AND (:sourceId IS NULL OR d.deviceSourceId = :sourceId)
              AND (:status IS NULL OR d.status = :status)
              AND (:complianceState IS NULL OR p.complianceState = :complianceState)
              AND (:operatingSystem IS NULL
                   OR LOWER(p.operatingSystem) = LOWER(CAST(:operatingSystem AS String)))
              AND (:search IS NULL
                   OR LOWER(d.deviceName) LIKE LOWER(CONCAT('%', CAST(:search AS String), '%'))
                   OR LOWER(d.serialNumber) LIKE LOWER(CONCAT('%', CAST(:search AS String), '%'))
                   OR LOWER(d.model) LIKE LOWER(CONCAT('%', CAST(:search AS String), '%')))
            """)
    Page<IotDevice> search(@Param("organizationId") Long organizationId,
                           @Param("sourceId") Long sourceId,
                           @Param("status") DeviceStatus status,
                           @Param("complianceState") ComplianceState complianceState,
                           @Param("operatingSystem") String operatingSystem,
                           @Param("search") String search,
                           Pageable pageable);

    @Query("""
            SELECT d.status, COUNT(d)
            FROM IotDevice d
            WHERE d.organizationId = :organizationId
              AND d.isDeleted = false
            GROUP BY d.status
            """)
    List<Object[]> countByStatus(@Param("organizationId") Long organizationId);

    @Query("""
            SELECT d.deviceClass, COUNT(d)
            FROM IotDevice d
            WHERE d.organizationId = :organizationId AND d.isDeleted = false
            GROUP BY d.deviceClass
            """)
    List<Object[]> countByDeviceClass(@Param("organizationId") Long organizationId);

    @Query("""
            SELECT d.ownership, COUNT(d)
            FROM IotDevice d
            WHERE d.organizationId = :organizationId AND d.isDeleted = false
            GROUP BY d.ownership
            """)
    List<Object[]> countByOwnership(@Param("organizationId") Long organizationId);

    @Query("""
            SELECT s.provider, COUNT(d)
            FROM IotDevice d
            JOIN IotDeviceSource s ON s.id = d.deviceSourceId
            WHERE d.organizationId = :organizationId AND d.isDeleted = false
            GROUP BY s.provider
            """)
    List<Object[]> countByProvider(@Param("organizationId") Long organizationId);

    @Query("""
            SELECT s.sourceXref, s.displayName, s.provider, COUNT(d)
            FROM IotDevice d
            JOIN IotDeviceSource s ON s.id = d.deviceSourceId
            WHERE d.organizationId = :organizationId AND d.isDeleted = false
            GROUP BY s.sourceXref, s.displayName, s.provider
            ORDER BY COUNT(d) DESC, s.displayName
            """)
    List<Object[]> countBySource(@Param("organizationId") Long organizationId);

    @Query("""
            SELECT COUNT(d)
            FROM IotDevice d
            JOIN IotDeviceEndpointPosture p ON p.deviceId = d.id
            WHERE d.organizationId = :organizationId
              AND d.isDeleted = false
              AND p.complianceState IS NOT NULL
              AND p.complianceState <> com.certmanagement.iot.enums.ComplianceState.COMPLIANT
            """)
    long countNonCompliant(@Param("organizationId") Long organizationId);

    @Query("""
            SELECT COUNT(d)
            FROM IotDevice d
            WHERE d.deviceSourceId = :sourceId
              AND d.isDeleted = false
              AND d.lastSeenInSourceAt >= :syncStartedAt
            """)
    long countSeenInSync(@Param("sourceId") Long sourceId,
                         @Param("syncStartedAt") OffsetDateTime syncStartedAt);

    long countByDeviceSourceIdAndIsDeletedFalse(Long deviceSourceId);

    @Query("""
            SELECT d.deviceSourceId, COUNT(d)
            FROM IotDevice d
            WHERE d.deviceSourceId IN :sourceIds AND d.isDeleted = false
            GROUP BY d.deviceSourceId
            """)
    List<Object[]> countByDeviceSourceIds(@Param("sourceIds") List<Long> sourceIds);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT d
            FROM IotDevice d
            WHERE d.deviceSourceId = :sourceId
              AND d.isDeleted = false
              AND d.status = com.certmanagement.iot.enums.DeviceStatus.REGISTERED
              AND (d.lastSeenInSourceAt IS NULL OR d.lastSeenInSourceAt < :syncStartedAt)
            ORDER BY d.id
            """)
    List<IotDevice> lockStaleDevices(@Param("sourceId") Long sourceId,
                                     @Param("syncStartedAt") OffsetDateTime syncStartedAt,
                                     Pageable pageable);

}
