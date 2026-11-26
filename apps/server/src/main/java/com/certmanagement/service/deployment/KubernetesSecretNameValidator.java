// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment;

import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
public class KubernetesSecretNameValidator {

    private static final Pattern DNS_SUBDOMAIN =
            Pattern.compile("^[a-z0-9]([a-z0-9\\-.]{0,251}[a-z0-9])?$");

    public boolean isValid(String secretName) {
        return secretName != null
                && !secretName.isBlank()
                && secretName.length() <= 253
                && DNS_SUBDOMAIN.matcher(secretName).matches();
    }
}
