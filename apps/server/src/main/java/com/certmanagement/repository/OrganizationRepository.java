// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.Organization;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OrganizationRepository extends JpaRepository<Organization, Long> {

    Optional<Organization> findByDomain(String domain);

    Optional<Organization> findByName(String name);

    @Query("SELECT o.id, o.name FROM Organization o WHERE o.id IN :ids")
    List<Object[]> findIdNameByIdIn(@Param("ids") java.util.Collection<Long> ids);

    Optional<Organization> findBySlug(String slug);

    boolean existsByDomain(String domain);

    boolean existsByDomainAndIdNot(String domain, Long id);

    boolean existsByName(String name);

    boolean existsByNameAndIdNot(String name, Long id);

    boolean existsBySlug(String slug);

    List<Organization> findByActiveTrue();

    /** Suspension state alone, for the per-request check in the JWT filter. */
    @Query("SELECT o.active AS active, o.isDeleted AS isDeleted FROM Organization o WHERE o.id = :id")
    Optional<ActivationStateProjection> findActivationStateById(@Param("id") Long id);

    @Query("SELECT COUNT(o) > 0 FROM Organization o WHERE o.id = :id AND o.isDeleted = false")
    boolean existsLiveById(@Param("id") Long id);

    @Query("SELECT o.orgType FROM Organization o WHERE o.id = :id")
    Optional<String> findOrgTypeById(@Param("id") Long id);

    @Query("SELECT o.name FROM Organization o WHERE o.id = :id")
    Optional<String> findNameById(@Param("id") Long id);

    /** An organization's id and type, for batch flag resolution. */
    interface OrgTypeView {
        Long getId();
        String getOrgType();
    }

    /** The types of a bounded batch of organizations (callers chunk the ids). */
    @Query("SELECT o.id AS id, o.orgType AS orgType FROM Organization o WHERE o.id IN :ids")
    List<OrgTypeView> findOrgTypesByIdIn(@Param("ids") java.util.Collection<Long> ids);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT o FROM Organization o WHERE o.id = :organizationId")
    Optional<Organization> findByIdForUpdate(@Param("organizationId") Long organizationId);

    /**
     * The notification categories a live organization turned off, comma-joined ("" for none); empty
     * for a deleted or unknown organization.
     */
    @NativeQuery("SELECT array_to_string(muted_notification_categories, ',') FROM organizations"
            + " WHERE id = :id AND is_deleted = false")
    Optional<String> findMutedNotificationCategories(@Param("id") long id);

    /** As {@link #findMutedNotificationCategories}, locking the row until the transaction ends. */
    @NativeQuery("SELECT array_to_string(muted_notification_categories, ',') FROM organizations"
            + " WHERE id = :id AND is_deleted = false FOR UPDATE")
    Optional<String> lockMutedNotificationCategories(@Param("id") long id);

    /** Replaces the organization's turned-off notification categories with the comma-joined {@code muted}. */
    @Modifying
    @NativeQuery("UPDATE organizations SET muted_notification_categories = string_to_array(:muted, ','),"
            + " updated_at = NOW() WHERE id = :id AND is_deleted = false")
    int updateMutedNotificationCategories(@Param("id") long id, @Param("muted") String muted);

    /** Returns IDs of ALL organizations including soft-deleted ones (bypasses @Where filter). */
    @NativeQuery("SELECT id FROM organizations")
    List<Long> findAllOrgIds();
}
