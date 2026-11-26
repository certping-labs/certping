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
 * CERT_RENEWED_NOT_DEPLOYED as the server publishes it (ProducerEnvelopes): CertResponseProcessor's
 * follow-up to CERT_RENEWAL_SUCCESS, sent through CertpingNotificationPublisher.
 */
class RenewedNotDeployedEmailTest {

    private static final String SUFFIX = " renewed — deploy it to keep it in use";
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
    void thePublishedEventDeserializesAndBecomesDeliverOnceUnderItsRequestId() {
        NotificationEvent event = ProducerEnvelopes.read(ProducerEnvelopes.renewedNotDeployed());

        assertThat(event.getNotificationAction()).isEqualTo(NotificationAction.CERT_RENEWED_NOT_DEPLOYED);
        assertThat(event.getNotificationType()).isEqualTo(NotificationType.ACCOUNT_EVENT);
        assertThat(event.getOrganizationId()).isEqualTo(42L);
        assertThat(event.getRoles()).containsExactly("ORGANIZATION_ADMIN");
        assertThat(event.getMessageId()).matches("msg-[0-9a-f]{24}");
        assertThat(event.getRequestId()).isEqualTo(ProducerEnvelopes.NOT_DEPLOYED_KEY);
        assertThat(event.getTemplateFields()).containsEntry("requestId", ProducerEnvelopes.NOT_DEPLOYED_KEY)
                .containsEntry("certificateXref", "CERT-NEW-2").containsEntry("previousValidTo", "2026-11-01T00:00Z");
        assertThat(event.isDeliverOnce()).as("the producer sets no flag").isFalse();

        DeliverOncePolicy.apply(event);

        assertThat(event.idempotencyKey()).isEqualTo(ProducerEnvelopes.NOT_DEPLOYED_KEY);
        assertThat(event.isDeliverOnce()).isTrue();
    }

    @Test
    void subjectFollowsTheContract() {
        assertThat(RenewedNotDeployedEmail.subject(ProducerEnvelopes.read(ProducerEnvelopes.renewedNotDeployed())))
                .isEqualTo("CertPing - Certificate for shop.example.com" + SUFFIX);
    }

    @Test
    void subjectWithoutADomainStaysReadable() {
        assertThat(RenewedNotDeployedEmail.subject(event(new HashMap<>())))
                .isEqualTo("CertPing - Certificate for your domain" + SUFFIX);
    }

    @Test
    void aLongDomainIsCutSoTheCallToDeploySurvivesOnOneLine() {
        String domain = "a\r\nBcc: x@example.net " + "d".repeat(200);

        String subject = RenewedNotDeployedEmail.subject(event(new HashMap<>(Map.of("domain", domain))));

        assertThat(subject).hasSize(150).endsWith("…" + SUFFIX)
                .startsWith("CertPing - Certificate for a Bcc: x@example.net ddd")
                .doesNotContain("\r").doesNotContain("\n");
    }

    @Test
    void theEllipsisNeverSplitsASurrogatePair() {
        String prefix = "CertPing - Certificate for ";
        int room = 150 - prefix.length() - SUFFIX.length() - 1;
        String domain = "d".repeat(room - 1) + "\uD83D\uDE00" + "tail";

        String subject = RenewedNotDeployedEmail.subject(event(new HashMap<>(Map.of("domain", domain))));

        assertThat(subject).isEqualTo(prefix + "d".repeat(room - 1) + "…" + SUFFIX);
    }

    @Test
    void emailExplainsTheManualDeployAndLinksTheCertificate() throws IOException {
        String html = render(ProducerEnvelopes.read(ProducerEnvelopes.renewedNotDeployed()));

        assertThat(html)
                .contains("The certificate for <strong>shop.example.com</strong> was renewed successfully.")
                .contains("Automatic deployment is turned off for your organization")
                .contains("before the current one expires on <strong>1 Nov 2026</strong>.")
                .contains("4 Jan 2027")
                .contains("CERT-NEW-2").contains("CERT-OLD-1")
                .contains("href=\"https://certping.example.com/cert-manager/manage/CERT-NEW-2\"")
                .contains(">View certificate<")
                .contains("mailto:support@example.com")
                .doesNotContain("{{");
    }

    @Test
    void anUnknownCurrentExpiryLeavesTheSentenceComplete() throws IOException {
        Map<String, Object> details = ProducerEnvelopes.renewalDetails();
        details.put("previousValidTo", "");

        assertThat(render(ProducerEnvelopes.read(ProducerEnvelopes.renewedNotDeployed(details, "CERT-NEW-2"))))
                .contains("Install the new certificate manually before the current one expires.");
    }

    @Test
    void missingFieldsRenderWithoutPlaceholdersAndLinkTheDashboard() throws IOException {
        String html = render(event(new HashMap<>()));

        assertThat(html)
                .contains("The certificate for <strong>your domain</strong>")
                .contains("href=\"https://certping.example.com\"")
                .doesNotContain("{{");
    }

    @Test
    void everyPublisherValueIsEscapedOnceAndCannotFormAPlaceholder() throws IOException {
        int ownLinks = links(render(ProducerEnvelopes.read(ProducerEnvelopes.renewedNotDeployed())));
        Map<String, Object> fields = new HashMap<>(Map.of("domain", INJECTED, "certificateXref", INJECTED,
                "previousCertificateXref", INJECTED, "validTo", INJECTED, "previousValidTo", INJECTED,
                "reason", INJECTED, "requestId", INJECTED));

        String html = render(event(fields));

        assertThat(html)
                .contains("The certificate for <strong>" + ENCODED + "</strong>")
                .contains("expires on <strong>" + ENCODED + "</strong>")
                .contains(">" + ENCODED + "<")
                .doesNotContain("<a href=\"https://evil")
                .doesNotContain("&amp;#123;").doesNotContain("{{");
        assertThat(links(html)).as("only the template's own links").isEqualTo(ownLinks);
        assertThat(html.split(Pattern.quote(ENCODED), -1).length - 1)
                .as("domain, phrase twice, both references, both dates").isEqualTo(7);
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
        return NotificationEvent.builder().notificationAction(NotificationAction.CERT_RENEWED_NOT_DEPLOYED)
                .organizationId(42L).templateFields(fields).build();
    }

    private String render(NotificationEvent event) throws IOException {
        when(emailConfig.getSupportAddress()).thenReturn("support@example.com");
        when(emailConfig.getFrontendBaseUrl()).thenReturn("https://certping.example.com");
        Map<String, Object> model = service.getModel(event);

        String html = smtp.render("cert-renewed-not-deployed", model);
        assertThat(acs.render("cert-renewed-not-deployed", model)).as("ACS and SMTP render alike").isEqualTo(html);
        return html;
    }
}
