// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, Long> {

    Optional<Permission> findByName(String name);

    List<Permission> findByNameIn(Collection<String> names);

    List<Permission> findByResource(String resource);

    List<Permission> findByResourceOrderByCreatedAtDesc(String resource);

    List<Permission> findAllByOrderByCreatedAtDesc();

    boolean existsByName(String name);
}
