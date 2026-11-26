// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByNameAndOrganizationId(String name, Long organizationId);

    /** A system role: the organization column itself is null (see {@code fk()} note in UserRepository). */
    @Query("SELECT r FROM Role r WHERE r.name = :name AND fk(r.organization) IS NULL")
    Optional<Role> findByNameAndOrganizationIsNull(@Param("name") String name);

    List<Role> findByOrganizationId(Long organizationId);

    List<Role> findByOrganizationIdOrderByUpdatedAtDesc(Long organizationId);

    List<Role> findByIsSystemRoleTrue();

    Optional<Role> findByIdAndOrganizationId(Long id, Long organizationId);

    @Query("SELECT r FROM Role r WHERE r.id = :id AND fk(r.organization) IS NULL")
    Optional<Role> findByIdAndOrganizationIsNull(@Param("id") Long id);

    List<Role> findByIsSystemRoleTrueOrderByUpdatedAtDesc();

    List<Role> findByName(String name);

    @Query("SELECT r.id FROM Role r WHERE r.organization.id = :orgId AND r.isSystemRole = false AND r.isDeleted = false")
    List<Long> findCustomRoleIdsByOrganizationId(@Param("orgId") Long orgId);

    @Transactional
    @Modifying
    @Query("UPDATE Role r SET r.isDeleted = true WHERE r.organization.id = :orgId AND r.isDeleted = false AND r.isSystemRole = false")
    int softDeleteCustomRolesByOrganizationId(@Param("orgId") Long orgId);

    @Transactional
    @Modifying
    @NativeQuery("UPDATE user_roles SET is_deleted = true WHERE role_id = :roleId AND is_deleted = false")
    int softDeleteUserRolesByRoleId(@Param("roleId") Long roleId);

    @Transactional
    @Modifying
    @NativeQuery("UPDATE role_permissions SET is_deleted = true WHERE role_id = :roleId AND is_deleted = false")
    int softDeleteRolePermissionsByRoleId(@Param("roleId") Long roleId);
}
