// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security.oidc;

import com.certmanagement.entity.Organization;
import com.certmanagement.entity.Role;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.RoleRepository;
import com.certmanagement.security.Permissions;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * The environment-configured OIDC provider as the two things the sign-in needs: a Spring
 * {@link ClientRegistration} (built from the issuer's discovery document, the first time it is asked
 * for, so a provider that is down at startup does not stop the server) and a transient
 * {@link SsoConfig} for the sign-in and provisioning path, never saved. IdP groups are not
 * mapped to roles here: every provisioned member gets {@link PlatformOidcProperties#getDefaultRole()},
 * and an administrator changes it afterwards. Group mapping is a CertPing Enterprise feature.
 */
@Component
@Slf4j
public class PlatformOidcRegistration {

    private final PlatformOidcProperties properties;
    private final OrganizationRepository organizationRepository;
    private final RoleRepository roleRepository;
    private volatile ClientRegistration registration;

    public PlatformOidcRegistration(PlatformOidcProperties properties, OrganizationRepository organizationRepository,
                                    RoleRepository roleRepository) {
        this.properties = properties;
        this.organizationRepository = organizationRepository;
        this.roleRepository = roleRepository;
    }

    public boolean configured() {
        return properties.configured();
    }

    public String displayName() {
        return properties.getDisplayName() == null || properties.getDisplayName().isBlank()
                ? "Single sign-on" : properties.getDisplayName();
    }

    /** True when {@code registrationId} is this provider's. */
    public boolean owns(String registrationId) {
        return configured() && PlatformOidcProperties.REGISTRATION_ID.equals(registrationId);
    }

    /** The Spring registration, discovered from the issuer on first use; null when not configured. */
    public ClientRegistration clientRegistration() {
        if (!configured()) {
            return null;
        }
        ClientRegistration current = registration;
        if (current == null) {
            synchronized (this) {
                if (registration == null) {
                    registration = discover();
                }
                current = registration;
            }
        }
        return current;
    }

    private ClientRegistration discover() {
        log.info("Discovering the OIDC provider at {}", properties.getIssuerUri());
        return ClientRegistrations.fromIssuerLocation(properties.getIssuerUri().trim())
                .registrationId(PlatformOidcProperties.REGISTRATION_ID)
                .clientId(properties.getClientId().trim())
                .clientSecret(properties.getClientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope(scopes())
                .clientName(displayName())
                .build();
    }

    Set<String> scopes() {
        Set<String> scopes = new LinkedHashSet<>();
        scopes.add("openid");
        String configured = properties.getScopes() == null ? "" : properties.getScopes();
        Arrays.stream(configured.split("[\\s,]+")).map(String::trim).filter(s -> !s.isEmpty()).forEach(scopes::add);
        return scopes;
    }

    /**
     * The configuration the sign-in reads, resolved against the database each time so a renamed
     * role or a deleted organization is seen at once. Empty when the organization does not exist.
     */
    public Optional<SsoConfig> ssoConfig() {
        if (!configured()) {
            return Optional.empty();
        }
        Optional<Organization> organization = findOrganization(properties.getOrganization().trim());
        if (organization.isEmpty()) {
            log.error("CERTPING_OIDC_ORGANIZATION '{}' matches no organization; single sign-on is refused",
                    properties.getOrganization());
            return Optional.empty();
        }
        return Optional.of(SsoConfig.builder()
                .organization(organization.get())
                .registrationId(PlatformOidcProperties.REGISTRATION_ID)
                .syncRolesOnFirstLogin(false)
                .autoProvisionEnabled(properties.isAutoProvision())
                .defaultRole(defaultRole().orElse(null))
                .build());
    }

    private Optional<Organization> findOrganization(String idOrSlug) {
        if (idOrSlug.chars().allMatch(Character::isDigit)) {
            Optional<Organization> byId = organizationRepository.findById(Long.parseLong(idOrSlug));
            if (byId.isPresent()) {
                return byId;
            }
        }
        return organizationRepository.findBySlug(idOrSlug);
    }

    /** The configured built-in role, or empty (the provisioning falls back to VIEWER). SUPER_ADMIN is refused. */
    Optional<Role> defaultRole() {
        String name = properties.getDefaultRole() == null ? "" : properties.getDefaultRole().trim().toUpperCase(Locale.ROOT);
        if (name.isEmpty() || Permissions.ROLE_SUPER_ADMIN.equals(name)) {
            if (!name.isEmpty()) {
                log.error("CERTPING_OIDC_DEFAULT_ROLE may not be {}; provisioned members get VIEWER", name);
            }
            return Optional.empty();
        }
        Optional<Role> role = roleRepository.findByNameAndOrganizationIsNull(name);
        if (role.isEmpty()) {
            log.error("CERTPING_OIDC_DEFAULT_ROLE '{}' is not a built-in role; provisioned members get VIEWER", name);
        }
        return role;
    }
}
