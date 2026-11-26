// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.CertificateCryptoMetadataEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateCryptoMetadataRepository extends JpaRepository<CertificateCryptoMetadataEntity, Long> {

    Optional<CertificateCryptoMetadataEntity> findByCertificateXref(String certificateXref);

    List<CertificateCryptoMetadataEntity> findAllByCertificateXrefIn(Collection<String> certificateXrefs);
}
