// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.user.UserDto;
import com.certmanagement.entity.Role;
import com.certmanagement.entity.User;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.AlertRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.PermissionGrantPolicy;
import com.certmanagement.service.audit.AccessAuditRecorder;
import com.certmanagement.service.cbom.CertificateInventoryChangedEvent;
import com.certmanagement.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import com.certmanagement.utils.RequestContextLogger;
import com.certmanagement.interceptor.RequestContextInterceptor;
import org.slf4j.Logger;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final UserDomainCertRepository userDomainCertRepository;
    private final AlertRepository alertRepository;
    private final RefreshTokenService refreshTokenService;
    private final ApplicationEventPublisher eventPublisher;
    private final PermissionGrantPolicy grantPolicy;
    private final AccessAuditRecorder accessAudit;
    private final PermissionFeatureVisibility featureVisibility;

    @Transactional(readOnly = true)
    public UserDto getUserById(Integer id) {
        return mapToDto(findUser(id));
    }

    @Transactional(readOnly = true)
    public UserDto getUserByEmail(String email) {
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));
        return mapToDto(user);
    }

    @Transactional(readOnly = true)
    public List<UserDto> getAllUsers() {
        return userRepository.findAll(Sort.by(Sort.Direction.DESC, "updatedAt")).stream()
            .map(this::mapToDto)
            .collect(Collectors.toList());
    }

    /**
     * The members of an organization. Permissions of features that are off for it, and roles made
     * only of them, are left out (one cached flag read for the whole list).
     */
    @Transactional(readOnly = true)
    public List<UserDto> getUsersByOrganization(Long organizationId) {
        PermissionFeatureVisibility.Hidden hidden = featureVisibility.forOrganization(organizationId);
        return userRepository.findByOrganizationIdOrderByUpdatedAtDesc(organizationId).stream()
            .map(user -> mapToDto(user, hidden))
            .collect(Collectors.toList());
    }

    /** One member, with the same feature-based hiding as {@link #getUsersByOrganization}. */
    @Transactional(readOnly = true)
    public UserDto getUserByIdAndOrganization(Integer id, Long organizationId) {
        return mapToDto(findUser(id, organizationId), featureVisibility.forOrganization(organizationId));
    }

    public UserDto updateUser(Integer id, UserDto dto) {
        return update(findUser(id), dto);
    }

    public UserDto updateUserForOrganization(Integer id, Long organizationId, UserDto dto) {
        return update(findUser(id, organizationId), dto);
    }

    public void deleteUser(Integer id) {
        softDelete(findUser(id));
    }

    public void deleteUserForOrganization(Integer id, Long organizationId) {
        softDelete(findUser(id, organizationId));
    }

    public void disableUser(Integer id) {
        disable(findUser(id));
    }

    public void disableUserForOrganization(Integer id, Long organizationId) {
        disable(findUser(id, organizationId));
    }

    private User findUser(Integer id) {
        return userRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id));
    }

    private User findUser(Integer id, Long organizationId) {
        return userRepository.findByIdAndOrganizationId(id, organizationId)
            .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id + " for organization: " + organizationId));
    }

    private UserDto update(User existing, UserDto dto) {
        // Prefer the explicit 'active' field; fall back to 'enabled' primitive for backward compat
        boolean active = dto.getActive() != null ? dto.getActive() : dto.isEnabled();
        grantPolicy.assertMayChange(grantPolicy.currentCaller(), existing, active, existing.getRoles());
        String emailBefore = existing.getEmail();
        boolean activeBefore = Boolean.TRUE.equals(existing.getActive());

        existing.setEmail(dto.getEmail());
        if (active && !activeBefore) {
            existing.enable();
        } else if (!active && activeBefore) {
            existing.disable();
        }
        if (dto.getDisplayName() != null) {
            existing.setDisplayName(dto.getDisplayName());
        }

        User updated = userRepository.save(existing);
        recordAccessChanges(updated, emailBefore, activeBefore);
        if (activeBefore && !active) {
            // Access tokens already stop at the filter's per-request active check; refresh tokens end here.
            refreshTokenService.revokeAllForUser(updated.getId());
        }
        contextLogger().info("Updated user with id: {} organization: {}", updated.getId(), organizationIdOf(updated));
        return mapToDto(updated);
    }

    private void softDelete(User user) {
        grantPolicy.assertMayDeactivate(grantPolicy.currentCaller(), user);
        Integer id = user.getId();
        Long organizationId = organizationIdOf(user);
        cascadeDeleteUser(id);
        user.setIsDeleted(true);
        user.setActive(false);
        userRepository.save(user);
        accessAudit.memberDeleted(user, user.getRoles());
        refreshTokenService.revokeAllForUser(id);
        contextLogger().info("Soft-deleted user with id: {} organization: {}", id, organizationId);
    }

    private void cascadeDeleteUser(Integer userId) {
        userRepository.softDeleteUserRolesByUserId(userId);
        userRepository.softDeleteUserPermissionsByUserId(userId);
        userDomainCertRepository.softDeleteByUserId(userId);
        eventPublisher.publishEvent(new CertificateInventoryChangedEvent());
        alertRepository.softDeleteByUserId(userId);
    }

    private void disable(User user) {
        grantPolicy.assertMayDeactivate(grantPolicy.currentCaller(), user);
        user.disable();
        userRepository.save(user);
        accessAudit.memberDisabled(user, user.getRoles(), null, AccessAuditRecorder.Actor.REQUEST);
        refreshTokenService.revokeAllForUser(user.getId());
        contextLogger().info("Disabled user with id: {} organization: {}", user.getId(), organizationIdOf(user));
    }

    /**
     * SSO links an identity to an existing account by email, ignoring case, so an email change moves
     * who can sign in as this user; it is recorded like the active flag. The row keeps that the email
     * changed, never an address.
     */
    private void recordAccessChanges(User user, String emailBefore, boolean activeBefore) {
        if (emailBefore == null ? user.getEmail() != null : !emailBefore.equalsIgnoreCase(user.getEmail())) {
            accessAudit.memberEmailChanged(user);
        }
        boolean activeAfter = Boolean.TRUE.equals(user.getActive());
        if (activeAfter != activeBefore) {
            if (activeAfter) {
                accessAudit.memberEnabled(user, null, null, AccessAuditRecorder.Actor.REQUEST);
            } else {
                accessAudit.memberDisabled(user, user.getRoles(), null, AccessAuditRecorder.Actor.REQUEST);
            }
        }
    }

    private static Long organizationIdOf(User user) {
        return user.getOrganization() != null ? user.getOrganization().getId() : null;
    }

    private UserDto mapToDto(User user) {
        return mapToDto(user, PermissionFeatureVisibility.Hidden.NOTHING);
    }

    /**
     * The user's role names, without roles made only of features that are off. With nothing off, the
     * roles' permissions are never touched, so a member list costs no permission reads.
     */
    private static Set<String> visibleRoleNames(User user, PermissionFeatureVisibility.Hidden hidden) {
        if (hidden.disabledFeatureKeys().isEmpty()) {
            return user.getRoleNames();
        }
        return user.getRoles().stream()
            .filter(role -> !hidden.hidesRole(role))
            .map(Role::getName)
            .collect(Collectors.toSet());
    }

    private static Set<String> visiblePermissionNames(User user, PermissionFeatureVisibility.Hidden hidden) {
        Set<String> names = user.getPermissionNames();
        if (hidden.disabledFeatureKeys().isEmpty()) {
            return names;
        }
        return names.stream().filter(name -> !hidden.hides(name)).collect(Collectors.toSet());
    }

    private UserDto mapToDto(User user, PermissionFeatureVisibility.Hidden hidden) {
        return UserDto.builder()
            .id(user.getId())
            .email(user.getEmail())
            .organizationId(organizationIdOf(user))
            .organizationName(user.getOrganization() != null ? user.getOrganization().getName() : null)
            .idpUserId(user.getIdpUserId())
            .username(user.getUsername())
            .displayName(user.getDisplayName())
            .authMethod(user.getAuthMethod() != null ? user.getAuthMethod().name() : null)
            .mustChangePassword(user.getMustChangePassword())
            .roles(visibleRoleNames(user, hidden))
            .permissions(visiblePermissionNames(user, hidden))
            .active(user.getActive())
            .enabled(Boolean.TRUE.equals(user.getActive()))
            .build();
    }

    /**
     * Creates a context-aware logger with request tracking IDs from the current request.
     */
    private Logger contextLogger() {
        return RequestContextLogger.getLogger(UserService.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }
}
