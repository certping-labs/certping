// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment;

import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
public class KubernetesNamespaceNameValidator {

    private static final Pattern DNS_LABEL =
            Pattern.compile("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$");

    public boolean isValid(String namespace) {
        return namespace != null
                && !namespace.isBlank()
                && namespace.length() <= 63
                && DNS_LABEL.matcher(namespace).matches();
    }
}
