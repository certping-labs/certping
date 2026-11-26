// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.config;

import com.certmanagement.service.AdminUserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * Ensures the hardcoded SUPER_ADMIN bootstrap account exists.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SuperAdminBootstrapInitializer implements ApplicationRunner {

    private final AdminUserService adminUserService;
    private final com.certmanagement.service.FirstOrganizationService firstOrganizationService;

    @Override
    public void run(ApplicationArguments args) {
        adminUserService.ensureBootstrapSuperAdmin();
        firstOrganizationService.ensure();
        log.debug("SUPER_ADMIN bootstrap initialization complete");
    }
}
