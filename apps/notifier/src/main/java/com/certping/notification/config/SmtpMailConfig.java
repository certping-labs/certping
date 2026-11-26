// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.mail.autoconfigure.MailSenderAutoConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * Conditionally enables Spring Mail auto-configuration only when the
 * email provider is set to "smtp". This prevents JavaMailSender and
 * MailHealthIndicator beans from being created when using ACS or other
 * non-SMTP providers.
 */
@Configuration
@ConditionalOnProperty(name = "email.provider", havingValue = "smtp")
@Import(MailSenderAutoConfiguration.class)
public class SmtpMailConfig {
}
