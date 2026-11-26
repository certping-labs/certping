// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.config.EmailConfig;
import com.certping.notification.enums.NotificationAction;
import com.certping.notification.model.NotificationEvent;
import com.certping.notification.repository.NotificationRepository;
import tools.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.mail.javamail.JavaMailSender;

import java.io.IOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * CERTPING_DNS_KEY_EXPIRING as the server's CertPingDnsKeyExpiryNotices sends it, rendered through both email
 * providers.
 */
class CertPingDnsKeyExpiringEmailTest {

    private static final String LEAD = "The CertPing DNS key <strong>example.com</strong> expires on "
            + "<strong>10 Nov 2026</strong> (UTC). It is the key starting <strong>cpk_live_ab12</strong>.";
    private static final String IMPACT = "After that, certificates validated through it stop renewing automatically. "
            + "They stay valid until they expire.";
    private static final String ACTION = "Create a new CertPing DNS key for this domain in CertPing before "
            + "<strong>10 Nov 2026</strong> (UTC). Renewals continue as soon as the new key is saved.";
    private static final String INJECTED = "{{dnsKeyLead}} <a href=\"https://evil.example\">x</a>";
    private static final String INJECTED_ESCAPED =
            "&#123;&#123;dnsKeyLead&#125;&#125; &lt;a href=&quot;https://evil.example&quot;&gt;x&lt;/a&gt;";

    private final EmailConfig emailConfig = mock(EmailConfig.class);
    private final NotificationService service = new NotificationService(mock(NotificationRepository.class),
            mock(EmailProvider.class), mock(ObjectMapper.class), emailConfig,
            mock(RoleEmailMapper.class), mock(RecipientDelivery.class), new EmailCopies(""), new SimpleMeterRegistry(),
            event -> Optional.empty());
    private final SmtpEmailService smtp = new SmtpEmailService(mock(JavaMailSender.class), new DefaultResourceLoader(),
            new DeliveryTimeouts("smtp", 30_000, 30_000, 30_000, Duration.ofSeconds(30), Duration.ofMinutes(5)));
    private final EmailService acs = new EmailService("", "noreply@example.com", new DefaultResourceLoader());

    @ParameterizedTest
    @ValueSource(ints = {30, 7})
    void theNoticeNamesTheKeyItsExpiryWhatStopsAndWhatToDo(int leadDays) throws IOException {
        Map<String, Object> fields = fields(leadDays);

        String html = render(fields);

        assertThat(html).contains(LEAD).contains(IMPACT).contains(ACTION).contains("Open CertPing")
                .doesNotContain("{{");
        if (leadDays == 7) {
            assertThat(html).contains(">Reminder<").contains(">Reminder: your CertPing DNS key expires soon<");
            assertThat(subject(fields)).isEqualTo("CertPing - Reminder: DNS key example.com expires on 10 Nov 2026");
        } else {
            assertThat(html).contains(">DNS key expiring<").contains(">Your CertPing DNS key expires soon<")
                    .doesNotContain("Reminder");
            assertThat(subject(fields)).isEqualTo("CertPing - DNS key example.com expires on 10 Nov 2026");
        }
    }

    @Test
    void anExpiryLateInTheDayIsNamedByItsUtcDay() {
        Map<String, Object> fields = fields(30);
        fields.put("expiresAt", "2026-11-10T23:30:00Z");

        assertThat(subject(fields)).isEqualTo("CertPing - DNS key example.com expires on 10 Nov 2026");
    }

    @Test
    void everyPublisherValueIsEscapedAndCannotFormAPlaceholder() throws IOException {
        Map<String, Object> fields = fields(30);
        fields.put("credentialName", INJECTED);
        fields.put("tokenPrefix", INJECTED);
        fields.put("expiresAt", INJECTED);

        String html = render(fields);

        assertThat(html)
                .doesNotContain("<a href=\"https://evil")
                .contains("The CertPing DNS key <strong>" + INJECTED_ESCAPED + "</strong> expires on <strong>"
                        + INJECTED_ESCAPED + "</strong> (UTC). It is the key starting <strong>" + INJECTED_ESCAPED
                        + "</strong>.")
                .doesNotContain("{{");
    }

    @Test
    void aNameOnSeveralLinesCannotAddAHeaderToTheSubject() {
        Map<String, Object> fields = fields(30);
        fields.put("credentialName", "example.com\r\nBcc: someone@evil.example");

        assertThat(subject(fields))
                .isEqualTo("CertPing - DNS key example.com Bcc: someone@evil.example expires on 10 Nov 2026");
    }

    @Test
    void withoutItsOptionalFieldsTheNoticeStillReads() throws IOException {
        Map<String, Object> fields = new HashMap<>(Map.of("idempotencyKey", "certping-dns-key-expiring:9:1:30"));

        String html = render(fields);

        assertThat(html)
                .contains("Your CertPing DNS key expires soon.")
                .contains("Create a new CertPing DNS key for this domain in CertPing. Renewals continue as soon "
                        + "as the new key is saved.")
                .doesNotContain("It is the key starting")
                .doesNotContain("<strong></strong>")
                .doesNotContain("{{");
        assertThat(subject(fields)).isEqualTo("CertPing - your CertPing DNS key expires soon");
    }

    @Test
    void eachNoticeIsDeliveredOnceUnderItsKeyExpiryAndLeadTime() {
        NotificationEvent event = NotificationEvent.builder()
                .notificationAction(NotificationAction.CERTPING_DNS_KEY_EXPIRING).organizationId(42L)
                .requestId("req-1").templateFields(fields(7)).build();

        DeliverOncePolicy.apply(event);

        assertThat(event.isDeliverOnce()).isTrue();
        assertThat(event.getNotificationKey()).isEqualTo("certping-dns-key-expiring:9:1794297600:7");
    }

    /** As the server's CertPingDnsKeyExpiryNotices.templateFields sends them. */
    private static Map<String, Object> fields(int leadDays) {
        return new HashMap<>(Map.of("organizationId", 42L, "organizationName", "Acme Ltd",
                "credentialName", "example.com", "tokenPrefix", "cpk_live_ab12", "expiresAt", "2026-11-10T08:00:00Z",
                "leadDays", leadDays, "idempotencyKey", "certping-dns-key-expiring:9:1794297600:" + leadDays));
    }

    private static String subject(Map<String, Object> fields) {
        return CertPingDnsKeyExpiringEmail.subject(event(fields));
    }

    private String render(Map<String, Object> fields) throws IOException {
        when(emailConfig.getSupportAddress()).thenReturn("support@example.com");
        when(emailConfig.getFrontendBaseUrl()).thenReturn("https://certping.example.com");
        Map<String, Object> model = service.getModel(event(fields));

        String html = smtp.render("certping-dns-key-expiring", model);
        assertThat(acs.render("certping-dns-key-expiring", model)).as("ACS and SMTP render alike").isEqualTo(html);
        return html;
    }

    private static NotificationEvent event(Map<String, Object> fields) {
        return NotificationEvent.builder().notificationAction(NotificationAction.CERTPING_DNS_KEY_EXPIRING)
                .organizationId(42L).templateFields(fields).build();
    }
}
