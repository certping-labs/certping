// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.config.MethodSecurityConfig;
import com.certmanagement.security.CustomPermissionEvaluator;
import com.certmanagement.service.PasswordHashRotationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import static com.certmanagement.security.Permissions.USERS_MANAGE;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * The rotation endpoints through real method security, with the application's permission evaluator:
 * an org admin holds {@code users:manage} but must not reach a platform-wide operation.
 */
@SpringJUnitConfig(PasswordHashRotationControllerSecurityTest.Config.class)
class PasswordHashRotationControllerSecurityTest {

    @Configuration
    @EnableMethodSecurity
    @Import({MethodSecurityConfig.class, CustomPermissionEvaluator.class})
    static class Config {
        @Bean
        PasswordHashRotationService rotationService() {
            return mock(PasswordHashRotationService.class);
        }

        @Bean
        PasswordHashRotationController controller(PasswordHashRotationService rotationService) {
            return new PasswordHashRotationController(rotationService);
        }
    }

    @Autowired private PasswordHashRotationController controller;

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void anOrgAdminWithUsersManageCannotRotateOrReadTheInventory() {
        authenticate("ROLE_ORGANIZATION_ADMIN", USERS_MANAGE);

        assertThatThrownBy(() -> controller.rotate(500)).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(controller::inventory).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void aSuperAdminCanRotateAndReadTheInventory() {
        authenticate("ROLE_SUPER_ADMIN");

        assertThatCode(() -> controller.rotate(500)).doesNotThrowAnyException();
        assertThatCode(controller::inventory).doesNotThrowAnyException();
    }

    private static void authenticate(String... authorities) {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                "user", null, AuthorityUtils.createAuthorityList(authorities)));
    }
}
