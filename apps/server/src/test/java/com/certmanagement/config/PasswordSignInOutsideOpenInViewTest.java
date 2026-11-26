// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.config;

import com.certmanagement.constants.Paths;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Password sign-in holds one pool connection at a time (AdminUserService.authenticate). Under open-in-view
 * the request would pin one for its whole length, and a wrong password's count would need a second.
 */
class PasswordSignInOutsideOpenInViewTest {

    @Test
    void bothPasswordSignInEndpointsRunOutsideOpenInView() {
        assertThat(WebConfig.OUTSIDE_OPEN_IN_VIEW).contains(Paths.AUTH_LOGIN, Paths.ADMIN_LOGIN);
    }
}
