// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.auth.LocalLoginRequest;
import com.certmanagement.dto.auth.UnifiedLoginRequest;
import com.certmanagement.entity.User;
import com.certmanagement.exception.UnauthorizedException;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.service.audit.AuthAuditRecorder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UnifiedAuthServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private AdminUserService adminUserService;

    @Mock private AuthAuditRecorder authAuditRecorder;
    @InjectMocks private UnifiedAuthService service;

    @Test
    void identifier_with_at_sign_looked_up_as_email_normalized() {
        User user = User.builder().id(1).email("alice@example.com").username("alice").build();
        when(userRepository.findByEmail("alice@example.com")).thenReturn(Optional.of(user));

        UnifiedLoginRequest req = UnifiedLoginRequest.builder()
                .identifier("ALICE@Example.COM").password("pw").build();
        service.login(req);

        ArgumentCaptor<LocalLoginRequest> captor = ArgumentCaptor.forClass(LocalLoginRequest.class);
        verify(adminUserService).authenticate(captor.capture());
        assertThat(captor.getValue().getUsername()).isEqualTo("alice");
        assertThat(captor.getValue().getPassword()).isEqualTo("pw");
    }

    @Test
    void identifier_without_at_sign_looked_up_as_username() {
        User user = User.builder().id(1).email("a@b.com").username("alice").build();
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));

        UnifiedLoginRequest req = UnifiedLoginRequest.builder()
                .identifier("alice").password("pw").build();
        service.login(req);

        ArgumentCaptor<LocalLoginRequest> captor = ArgumentCaptor.forClass(LocalLoginRequest.class);
        verify(adminUserService).authenticate(captor.capture());
        assertThat(captor.getValue().getUsername()).isEqualTo("alice");
    }

    @Test
    void unknown_identifier_returns_opaque_401() {
        when(userRepository.findByEmail("a@b.com")).thenReturn(Optional.empty());

        UnifiedLoginRequest req = UnifiedLoginRequest.builder()
                .identifier("a@b.com").password("pw").build();
        assertThatThrownBy(() -> service.login(req))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("Invalid username or password");
    }
}
