// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security.oidc;

import com.certmanagement.entity.Organization;
import com.certmanagement.entity.Role;
import lombok.Builder;
import lombok.Value;

/**
 * The settings one OIDC sign-in runs with, built by {@link PlatformOidcRegistration} from the environment
 * for each sign-in and never stored.
 */
@Value
@Builder
public class SsoConfig {

    Organization organization;
    String registrationId;
    /** JSON object naming the claim for each user field; {@code userId} picks the stable identifier. */
    String attributeMapping;
    /** JSON object mapping IdP roles or groups to application role names. */
    String roleMapping;
    String rolesClaimName;
    String groupsClaimName;
    /** Map IdP roles or groups at first sign-in; otherwise the member gets {@link #defaultRole}. */
    Boolean syncRolesOnFirstLogin;
    Boolean autoProvisionEnabled;
    Role defaultRole;
}
