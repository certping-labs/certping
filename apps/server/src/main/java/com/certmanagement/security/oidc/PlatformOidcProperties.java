// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security.oidc;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.stereotype.Component;

/**
 * One OpenID Connect provider for the whole installation, set by environment variables
 * ({@code CERTPING_OIDC_*}), for self-hosted installations whose people already have an identity
 * provider. Nothing is stored in the database and there is no administration screen: the provider is
 * part of the deployment, like the database password. Setting {@code issuer-uri}, {@code client-id},
 * {@code client-secret} and {@code organization} together turns it on; anything missing leaves sign-in
 * local only.
 */
@Component
@ConfigurationProperties(prefix = "certping.oidc")
@Getter
@Setter
public class PlatformOidcProperties {

    /** The registration id in every URL: {@code /oauth2/authorization/sso}, {@code /login/oauth2/code/sso}. */
    public static final String REGISTRATION_ID = "sso";

    /** The provider's issuer, whose {@code /.well-known/openid-configuration} supplies the endpoints. */
    private String issuerUri;
    private String clientId;
    private String clientSecret;
    /** The organization people are signed into: its numeric id or its slug. */
    private String organization;
    /** What the sign-in button says. */
    private String displayName = "Single sign-on";
    /** Space-separated; {@code openid} is added when missing. */
    private String scopes = "openid profile email";
    /** The built-in role a person provisioned at first sign-in gets; never SUPER_ADMIN. */
    private String defaultRole = "VIEWER";
    /** Create a member at first sign-in; off means only invited members can use the provider. */
    private boolean autoProvision = true;

    public boolean configured() {
        return notBlank(issuerUri) && notBlank(clientId) && notBlank(clientSecret) && notBlank(organization);
    }

    private static boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }

    /** Matches when the provider is {@link #configured()}, read before the properties bean exists. */
    public static class Configured implements Condition {

        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            return Binder.get(context.getEnvironment()).bind("certping.oidc", PlatformOidcProperties.class)
                    .map(PlatformOidcProperties::configured).orElse(false);
        }
    }
}
