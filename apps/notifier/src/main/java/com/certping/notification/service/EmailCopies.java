// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.interceptor.RequestContextInterceptor;
import com.certping.notification.model.NotificationEvent;
import com.certping.notification.utils.RequestContextLogger;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * The cc addresses of an email event that can be sent to: a bare address (no display name or group)
 * whose domain is allowed, each once, and not already a recipient. Anything else is dropped rather
 * than failing the email for its recipients.
 */
@Component
class EmailCopies {

    static final int MAX_CC = 10;

    private final Set<String> allowedDomains;

    EmailCopies(@Value("${notification.cc-allowed-domains:}") String allowedDomains) {
        this.allowedDomains = Arrays.stream(allowedDomains == null ? new String[0] : allowedDomains.split(","))
                .map(domain -> domain.trim().toLowerCase(Locale.ROOT))
                .filter(domain -> !domain.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
    }

    List<String> of(NotificationEvent event, Collection<String> recipients) {
        List<String> cc = event.getCc();
        if (cc == null || cc.isEmpty()) {
            return List.of();
        }
        Set<String> taken = new HashSet<>();
        if (recipients != null) {
            recipients.forEach(recipient -> taken.add(recipient.trim().toLowerCase(Locale.ROOT)));
        }
        List<String> copies = new ArrayList<>();
        for (String candidate : cc) {
            if (copies.size() == MAX_CC) {
                break;
            }
            String address = bareAddress(candidate);
            if (address == null) {
                continue;
            }
            String domain = address.substring(address.indexOf('@') + 1).toLowerCase(Locale.ROOT);
            if (!allowedDomains.contains(domain)) {
                contextLogger().warn("Dropped a cc address at a domain that is not allowed: {}", domain);
                continue;
            }
            if (taken.add(address.toLowerCase(Locale.ROOT))) {
                copies.add(address);
            }
        }
        return List.copyOf(copies);
    }

    /**
     * The recipient whose message carries the copies: the one whose lower-cased address sorts first,
     * so every attempt picks the same one and a deliver-once retry never copies twice.
     */
    static int carrier(List<String> recipients) {
        return IntStream.range(0, recipients.size()).boxed()
                .min(Comparator.comparing(i -> recipients.get(i).toLowerCase(Locale.ROOT)))
                .orElse(-1);
    }

    static void send(EmailProvider provider, String to, List<String> copies, String subject, String templateName,
                     Map<String, Object> model) {
        if (copies.isEmpty()) {
            provider.sendTemplatedEmail(to, subject, templateName, model);
        } else {
            provider.sendTemplatedEmail(to, copies, subject, templateName, model);
        }
    }

    /** {@code a@example.com} as written, or null for a display name, a group, a dotless domain or anything malformed. */
    static String bareAddress(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            return null;
        }
        try {
            InternetAddress parsed = new InternetAddress(candidate.trim(), true);
            parsed.validate();
            String address = parsed.getAddress();
            if (parsed.isGroup() || parsed.getPersonal() != null || address == null) {
                return null;
            }
            int at = address.lastIndexOf('@');
            String domain = at < 0 ? "" : address.substring(at + 1);
            if (domain.indexOf('.') <= 0 || domain.endsWith(".")) {
                return null;
            }
            return address;
        } catch (AddressException e) {
            return null;
        }
    }

    private Logger contextLogger() {
        return RequestContextLogger.getLogger(EmailCopies.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }
}
