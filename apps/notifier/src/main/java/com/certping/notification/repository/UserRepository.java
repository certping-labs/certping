// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.repository;

import com.certping.notification.model.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Read-only repository for the {@code users} table.
 * Used solely for resolving notification recipients by role or user ID.
 */
@Repository
public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    /**
     * Find the email of an active user by their ID.
     */
    @Query("SELECT u.email FROM UserEntity u WHERE u.id = :userId AND u.active = true")
    Optional<String> findEmailByUserId(@Param("userId") Long userId);

    /** The email of an active, undeleted member of the organization; empty for anyone else. */
    @NativeQuery("SELECT u.email FROM users u WHERE u.id = :userId AND u.organization_id = :organizationId "
            + "AND u.active = true AND u.is_deleted = false")
    Optional<String> findEmailByUserIdInOrganization(@Param("userId") Long userId,
                                                     @Param("organizationId") Long organizationId);

    /**
     * Find emails of all active users who have a specific role in a given organization.
     */
    @NativeQuery("SELECT DISTINCT u.email FROM users u " +
            "JOIN user_roles ur ON u.id = ur.user_id " +
            "JOIN roles r ON ur.role_id = r.id " +
            "WHERE LOWER(r.name) = LOWER(:roleName) AND u.organization_id = :organizationId AND u.active = true")
    List<String> findEmailsByRoleAndOrganization(@Param("roleName") String roleName,
                                           @Param("organizationId") Long organizationId);

    /**
     * Emails of the active holders of a platform role (a role with no organization), such as
     * SUPER_ADMIN. The same query as the server's UserRepository.findActivePlatformRoleEmails.
     */
    @NativeQuery("SELECT DISTINCT u.email FROM users u " +
            "JOIN user_roles ur ON u.id = ur.user_id " +
            "JOIN roles r ON ur.role_id = r.id " +
            "WHERE r.name = :roleName " +
            "AND r.organization_id IS NULL " +
            "AND u.active = true " +
            "AND u.is_deleted = false " +
            "AND ur.is_deleted = false " +
            "AND r.is_deleted = false")
    List<String> findActivePlatformRoleEmails(@Param("roleName") String roleName);
}
