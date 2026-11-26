// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Binds {@code app.auth.password-pepper.*} from {@code application.yaml}.
 *
 * <p>Shape:
 * <pre>
 * app:
 *   auth:
 *     password-pepper:
 *       active-version: v1
 *       keys:
 *         v1: ${PASSWORD_PEPPER_V1:}
 *         v2: ${PASSWORD_PEPPER_V2:}
 *         ...
 * </pre>
 *
 * <p>Slots are pre-declared in yaml so Spring's relaxed-binding can resolve
 * each {@code keys.vN} entry from its corresponding {@code PASSWORD_PEPPER_VN}
 * environment variable. Empty slots are tolerated and filtered out by
 * {@link PepperedPasswordEncoder}, so a freshly-deployed environment with only
 * V1 set works fine and a rotation only requires populating V2 (no yaml edit).
 *
 * <p>When you need a slot beyond what {@code application.yaml} declares
 * (e.g. v5), add a line for it in yaml and set the matching
 * {@code PASSWORD_PEPPER_V5} environment variable wherever the deployment keeps its secrets.
 */
@Component
@ConfigurationProperties(prefix = "app.auth.password-pepper")
@Getter
@Setter
public class PasswordPepperProperties {

    /** Label of the pepper version used for new encodes. e.g. {@code "v1"}, {@code "v2"}. */
    private String activeVersion;

    /** Map of version label → base64-encoded AES-256 key. Blank values dropped at encoder construction. */
    private Map<String, String> keys = new LinkedHashMap<>();
}
