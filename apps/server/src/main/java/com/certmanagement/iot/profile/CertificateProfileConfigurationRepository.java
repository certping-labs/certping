// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import org.springframework.data.jpa.repository.JpaRepository;

public interface CertificateProfileConfigurationRepository
        extends JpaRepository<CertificateProfileConfiguration, Long> {
}
