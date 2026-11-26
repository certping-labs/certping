// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import java.util.Set;

public record IntuneSession(String token, Set<String> roles) {
    public IntuneSession(String token) {
        this(token, Set.of());
    }

    public IntuneSession {
        roles = roles == null ? Set.of() : Set.copyOf(roles);
    }
}
