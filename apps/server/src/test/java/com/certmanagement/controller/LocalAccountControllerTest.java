// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.auth.ChangePasswordRequest;
import com.certmanagement.dto.auth.ForgotPasswordRequest;
import com.certmanagement.dto.auth.ResetPasswordRequest;
import com.certmanagement.dto.auth.SetupRequest;
import com.certmanagement.entity.User;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ConflictException;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.AdminUserService;
import com.certmanagement.service.PasswordResetService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** First-run setup and the local password endpoints, the only account endpoints the open edition has. */
@ExtendWith(MockitoExtension.class)
class LocalAccountControllerTest {

    @Mock private PasswordResetService passwordResetService;
    @Mock private AdminUserService adminUserService;
    @Mock private com.certmanagement.service.FirstOrganizationService firstOrganizationService;

    @InjectMocks private LocalAccountController controller;

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    @Test
    void setupStatusSaysWhetherTheFirstAdminStillHasToBeCreated() {
        when(adminUserService.isSetupRequired()).thenReturn(true);
        assertThat(controller.setupStatus().getBody()).containsEntry("setupRequired", true);

        when(adminUserService.isSetupRequired()).thenReturn(false);
        assertThat(controller.setupStatus().getBody()).containsEntry("setupRequired", false);
    }

    @Test
    void setupCreatesTheFirstSuperAdminAndAnswersCreated() {
        SetupRequest req = SetupRequest.builder().username("owner").email("owner@example.com")
                .password("Correct-Horse-Battery-9").build();
        when(adminUserService.createFirstSuperAdmin(req))
                .thenReturn(User.builder().username("owner").email("owner@example.com").build());

        ResponseEntity<Map<String, Object>> result = controller.setup(req);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(result.getBody()).containsEntry("username", "owner").containsEntry("email", "owner@example.com")
                .containsKey("message");
        // The password never comes back.
        assertThat(result.getBody().values()).noneMatch(v -> String.valueOf(v).contains("Correct-Horse"));
    }

    @Test
    void setupIsAConflictOnceAnyUserExists() {
        SetupRequest req = SetupRequest.builder().username("second").email("second@example.com")
                .password("Correct-Horse-Battery-9").build();
        when(adminUserService.createFirstSuperAdmin(req)).thenThrow(new ConflictException("Setup has already been completed"));

        assertThatThrownBy(() -> controller.setup(req)).isInstanceOf(ConflictException.class);
    }

    @Test
    void forgotPasswordAlwaysAnswersOkWithoutSayingWhetherTheAccountExists() {
        ForgotPasswordRequest req = new ForgotPasswordRequest();
        req.setEmail("u@example.com");

        ResponseEntity<Map<String, String>> result = controller.forgotPassword(req);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody().get("message")).contains("If an account exists");
        verify(passwordResetService).forgotPassword(eq("u@example.com"), any());
    }

    @Test
    void resetPasswordDelegatesWithTheToken() {
        ResetPasswordRequest req = new ResetPasswordRequest();

        ResponseEntity<Map<String, String>> result = controller.resetPassword("tok", req);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        verify(passwordResetService).resetPassword(eq("tok"), eq(req), any());
    }

    @Test
    void changePasswordUsesTheSignedInUser() {
        GatewayRequestContext.set(7, "1", "req-1", "u@example.com");
        ChangePasswordRequest req = new ChangePasswordRequest();

        ResponseEntity<Map<String, String>> result = controller.changePassword(req, new org.springframework.mock.web.MockHttpServletRequest());

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        verify(adminUserService).changePassword(7, req, null);
    }

    @Test
    void changePasswordWithoutAnIdentityIsRefused() {
        assertThatThrownBy(() -> controller.changePassword(new ChangePasswordRequest(), null))
                .isInstanceOf(BadRequestException.class);
        verify(adminUserService, never()).changePassword(any(), any(), any());
    }
}
