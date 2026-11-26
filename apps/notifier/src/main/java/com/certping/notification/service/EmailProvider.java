// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import java.util.List;
import java.util.Map;

/**
 * Email provider interface to support multiple implementations (ACS, SMTP, etc.)
 */
public interface EmailProvider {
    void sendTemplatedEmail(String to, String subject, String templateName, Map<String, Object> model);

    /**
     * The same email with copies to {@code cc}. The copies ride on the one message to {@code to}:
     * they get no delivery or record of their own.
     */
    void sendTemplatedEmail(String to, List<String> cc, String subject, String templateName, Map<String, Object> model);
}
