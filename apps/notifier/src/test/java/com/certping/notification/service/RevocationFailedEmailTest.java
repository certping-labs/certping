// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.config.EmailConfig;
import com.certping.notification.enums.NotificationAction;
import com.certping.notification.enums.NotificationType;
import com.certping.notification.model.NotificationEvent;
import com.certping.notification.repository.NotificationRepository;
import tools.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.mail.javamail.JavaMailSender;

import java.io.IOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * CERT_REVOCATION_FAILED as the server publishes it (ProducerEnvelopes): CertResponseProcessor's answer to
 * an agent error on a revocation command, sent through CertpingNotificationPublisher.
 */
class RevocationFailedEmailTest {

    private static final String INJECTED = "{{templateFields}} {{domain}} <a href=\"https://evil.example\">x</a>";
    private static final String ENCODED = "&#123;&#123;templateFields&#125;&#125; &#123;&#123;domain&#125;&#125; "
            + "&lt;a href=&quot;https://evil.example&quot;&gt;x&lt;/a&gt;";

    private final EmailConfig emailConfig = mock(EmailConfig.class);
    private final NotificationService service = new NotificationService(mock(NotificationRepository.class),
            mock(EmailProvider.class), mock(ObjectMapper.class), emailConfig,
            mock(RoleEmailMapper.class), mock(RecipientDelivery.class), new EmailCopies(""), new SimpleMeterRegistry(),
            event -> java.util.Optional.empty());
    private final SmtpEmailService smtp = new SmtpEmailService(mock(JavaMailSender.class), new DefaultResourceLoader(),
            new DeliveryTimeouts("smtp", 30_000, 30_000, 30_000, Duration.ofSeconds(30), Duration.ofMinutes(5)));
    private final EmailService acs = new EmailService("", "noreply@example.com", new DefaultResourceLoader());

    @Test
    void thePublishedEventDeserializesWithItsAction() {
        NotificationEvent event = ProducerEnvelopes.readAsListener(ProducerEnvelopes.revocationFailed());

        assertThat(event.getNotificationAction()).isEqualTo(NotificationAction.CERT_REVOCATION_FAILED);
        assertThat(event.getNotificationType()).isEqualTo(NotificationType.ACCOUNT_EVENT);
        assertThat(event.getOrganizationId()).isEqualTo(42L);
        assertThat(event.getRoles()).containsExactly("ORGANIZATION_ADMIN");
        assertThat(event.getRequestId()).isEqualTo(ProducerEnvelopes.REVOCATION_REQUEST_ID);
        assertThat(event.getTemplateFields()).containsEntry("errorCode", "CA_UNAVAILABLE")
                .containsEntry("certificateXref", "CERT-REV-7");
        assertThat(event.isDeliverOnce()).isFalse();
    }

    @Test
    void subjectNamesTheDomain() {
        assertThat(RevocationFailedEmail.subject(ProducerEnvelopes.read(ProducerEnvelopes.revocationFailed())))
                .isEqualTo("CertPing - Revoking the certificate for shop.example.com failed");
    }

    @Test
    void subjectWithoutADomainStaysReadableAndOnOneLine() {
        assertThat(RevocationFailedEmail.subject(event(new HashMap<>(Map.of("domain", "")))))
                .isEqualTo("CertPing - Revoking the certificate for your domain failed");
        assertThat(RevocationFailedEmail.subject(event(new HashMap<>(Map.of("domain", "a.com\r\nBcc: x@example.net")))))
                .isEqualTo("CertPing - Revoking the certificate for a.com Bcc: x@example.net failed");
    }

    @Test
    void emailSaysTheCertificateIsStillTrustedAndLinksItsPage() throws IOException {
        String html = render(ProducerEnvelopes.read(ProducerEnvelopes.revocationFailed()));

        assertThat(html)
                .contains("Revoking the certificate for <strong>shop.example.com</strong> did not complete, "
                        + "so it is still valid and trusted.")
                .contains("Try again from the certificate page, or contact us at")
                .containsPattern(">Error code</td>\\s*<td[^>]*>CA_UNAVAILABLE</td>")
                .containsPattern(">Request ID</td>\\s*<td[^>]*>revoke-req-3</td>")
                .contains("CERT-REV-7")
                .contains("href=\"https://certping.example.com/cert-manager/manage/CERT-REV-7\"")
                .contains("mailto:support@example.com")
                .doesNotContain("{{");
    }

    @Test
    void missingFieldsRenderWithoutPlaceholdersAndLinkTheDashboard() throws IOException {
        String html = render(event(new HashMap<>(Map.of("errorCode", "", "domain", "", "requestId", ""))));

        assertThat(html)
                .contains("Revoking the certificate for <strong>your domain</strong> did not complete")
                .containsPattern(">Error code</td>\\s*<td[^>]*>&ndash;</td>")
                .containsPattern(">Certificate XRef</td>\\s*<td[^>]*>&ndash;</td>")
                .contains("href=\"https://certping.example.com\"")
                .doesNotContain("{{");
        assertThat(render(event(null))).contains("<strong>your domain</strong>").doesNotContain("{{");
    }

    @Test
    void everyPublisherValueIsEscapedOnceAndCannotFormAPlaceholder() throws IOException {
        int ownLinks = links(render(ProducerEnvelopes.read(ProducerEnvelopes.revocationFailed())));
        Map<String, Object> fields = new HashMap<>(Map.of("domain", INJECTED, "errorCode", INJECTED,
                "certificateXref", INJECTED, "requestId", INJECTED));

        String html = render(event(fields));

        assertThat(html)
                .contains("Revoking the certificate for <strong>" + ENCODED + "</strong>")
                .doesNotContain("<a href=\"https://evil")
                .doesNotContain("&amp;#123;").doesNotContain("{{");
        assertThat(links(html)).as("only the template's own links").isEqualTo(ownLinks);
        assertThat(html.split(Pattern.quote(ENCODED), -1).length - 1)
                .as("preheader, lead and the four detail rows").isEqualTo(6);
    }

    @Test
    void theReferenceIsPathEncodedInTheLink() throws IOException {
        String html = render(event(new HashMap<>(Map.of("certificateXref", "a\"b/c?d {x}"))));

        assertThat(html).contains("/cert-manager/manage/a%22b%2Fc%3Fd%20%7Bx%7D\"");
    }

    private static int links(String html) {
        return html.split("<a ", -1).length - 1;
    }

    private static NotificationEvent event(Map<String, Object> fields) {
        return NotificationEvent.builder().notificationAction(NotificationAction.CERT_REVOCATION_FAILED)
                .organizationId(42L).templateFields(fields).build();
    }

    private String render(NotificationEvent event) throws IOException {
        when(emailConfig.getSupportAddress()).thenReturn("support@example.com");
        when(emailConfig.getFrontendBaseUrl()).thenReturn("https://certping.example.com");
        Map<String, Object> model = service.getModel(event);

        String html = smtp.render("cert-revocation-failed", model);
        assertThat(acs.render("cert-revocation-failed", model)).as("ACS and SMTP render alike").isEqualTo(html);
        return html;
    }
}
