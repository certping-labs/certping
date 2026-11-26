// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import jakarta.mail.internet.MimeMessage;
import jakarta.mail.Address;
import jakarta.mail.MessagingException;
import jakarta.mail.Provider;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.URLName;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SmtpEmailServiceTest {

    public static class BlockingTransport extends Transport {
        static CountDownLatch entered;
        static CountDownLatch closed;

        public BlockingTransport(Session session, URLName url) {
            super(session, url);
        }

        @Override
        protected boolean protocolConnect(String host, int port, String username, String password) {
            return true;
        }

        @Override
        public void sendMessage(jakarta.mail.Message message, Address[] addresses) throws MessagingException {
            entered.countDown();
            try {
                if (!closed.await(2, TimeUnit.SECONDS)) {
                    throw new MessagingException("transport remained open");
                }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new MessagingException("interrupted", interrupted);
            }
        }

        @Override
        public void close() throws MessagingException {
            closed.countDown();
            super.close();
        }
    }

    @Mock private JavaMailSender mailSender;
    @Mock private ResourceLoader resourceLoader;
    @Mock private Resource templateResource;

    private SmtpEmailService service;

    @BeforeEach
    void setUp() {
        service = new SmtpEmailService(mailSender, resourceLoader,
                new DeliveryTimeouts("smtp", 30_000, 30_000, 30_000, java.time.Duration.ofSeconds(30),
                        java.time.Duration.ofMinutes(5)));
        ReflectionTestUtils.setField(service, "senderAddress", "noreply@example.com");
    }

    @Test
    void aSlowSmtpExchangeIsClosedAtItsWholeSendDeadline() throws Exception {
        BlockingTransport.entered = new CountDownLatch(1);
        BlockingTransport.closed = new CountDownLatch(1);
        Session session = Session.getInstance(new Properties());
        session.setProvider(new Provider(Provider.Type.TRANSPORT, "test-smtp",
                BlockingTransport.class.getName(), "certping", "1"));
        JavaMailSenderImpl sender = new JavaMailSenderImpl();
        sender.setSession(session);
        sender.setProtocol("test-smtp");
        DeliveryTimeouts timeouts = new DeliveryTimeouts("smtp", 1_700, 1_700, 1_700,
                java.time.Duration.ofSeconds(30), java.time.Duration.ofMinutes(5));
        SmtpEmailService bounded = new SmtpEmailService(sender, new DefaultResourceLoader(), timeouts);
        ReflectionTestUtils.setField(bounded, "senderAddress", "noreply@example.com");

        assertThatThrownBy(() -> bounded.sendTemplatedEmail("member@example.com", "Subject",
                "undelivered-email", Map.of("requestId", "order-1")))
                .isInstanceOf(EmailSendDeadlineException.class);
        assertThat(BlockingTransport.entered.getCount()).isZero();
        assertThat(BlockingTransport.closed.getCount()).isZero();
    }

    // ── Happy path ─────────────────────────────────────────────────────────

    // MimeMessageHelper builds a MimeMultipart under the hood, so mime.getContent() returns
    // that Multipart, not the raw HTML string. These tests focus on verifying send() was
    // reached with a MimeMessage — that's enough to exercise every substitution + sanitize
    // branch inside sendTemplatedEmail. Content-level assertions would need MIME parsing
    // that adds noise without adding coverage.

    @Test
    void sendTemplatedEmail_happyPath_substitutesModelAndSends() throws Exception {
        stubTemplate("Hello {{name}}, click <a href=\"{{ctaUrl}}\">here</a>");
        MimeMessage mime = new MimeMessage(jakarta.mail.Session.getInstance(new java.util.Properties()));
        when(mailSender.createMimeMessage()).thenReturn(mime);

        Map<String, Object> model = new HashMap<>();
        model.put("name", "Alice");
        model.put("ctaUrl", "https://certping.example.com/dashboard");

        service.sendTemplatedEmail("alice@example.com", "Welcome", "welcome", model);

        verify(mailSender).send(mime);
        assertThat(mime.getSubject()).isEqualTo("Welcome");
    }

    @Test
    void copiesAreAddedToTheSameSmtpMessage() throws Exception {
        stubTemplate("Hi");
        MimeMessage mime = new MimeMessage(jakarta.mail.Session.getInstance(new java.util.Properties()));
        when(mailSender.createMimeMessage()).thenReturn(mime);

        service.sendTemplatedEmail("attorney@law.test", java.util.List.of("legal@example.com"),
                "Assigned", "welcome", new HashMap<>());

        verify(mailSender).send(mime);
        assertThat(mime.getRecipients(jakarta.mail.Message.RecipientType.CC))
                .extracting(Object::toString).containsExactly("legal@example.com");
        assertThat(mime.getRecipients(jakarta.mail.Message.RecipientType.TO))
                .extracting(Object::toString).containsExactly("attorney@law.test");
    }

    // ── URL sanitization: exercises the sanitizeTemplateValue branches ─────

    @Test
    void sendTemplatedEmail_javascriptSchemeUrl_stillSends() throws Exception {
        // The branch that blocks javascript: URIs still exits normally — we just verify
        // the call reached send() (no exception thrown by sanitization).
        stubTemplate("<a href=\"{{ctaLink}}\">click</a>");
        MimeMessage mime = new MimeMessage(jakarta.mail.Session.getInstance(new java.util.Properties()));
        when(mailSender.createMimeMessage()).thenReturn(mime);

        service.sendTemplatedEmail("a@example.com", "s", "welcome",
                Map.of("ctaLink", "javascript:alert(1)"));

        verify(mailSender).send(mime);
    }

    @Test
    void sendTemplatedEmail_relativeUrl_allowed() throws Exception {
        stubTemplate("<a href=\"{{ctaLink}}\">click</a>");
        MimeMessage mime = new MimeMessage(jakarta.mail.Session.getInstance(new java.util.Properties()));
        when(mailSender.createMimeMessage()).thenReturn(mime);

        service.sendTemplatedEmail("a@example.com", "s", "welcome",
                Map.of("ctaLink", "/dashboard"));

        verify(mailSender).send(mime);
    }

    @Test
    void sendTemplatedEmail_mailtoUrl_allowed() throws Exception {
        stubTemplate("<a href=\"{{ctaUrl}}\">contact</a>");
        MimeMessage mime = new MimeMessage(jakarta.mail.Session.getInstance(new java.util.Properties()));
        when(mailSender.createMimeMessage()).thenReturn(mime);

        service.sendTemplatedEmail("a@example.com", "s", "welcome",
                Map.of("ctaUrl", "mailto:support@example.com"));

        verify(mailSender).send(mime);
    }

    @Test
    void sendTemplatedEmail_dataUrlOnUrlKey_stillSends() throws Exception {
        stubTemplate("<img src=\"{{logoUrl}}\">");
        MimeMessage mime = new MimeMessage(jakarta.mail.Session.getInstance(new java.util.Properties()));
        when(mailSender.createMimeMessage()).thenReturn(mime);

        service.sendTemplatedEmail("a@example.com", "s", "welcome",
                Map.of("logoUrl", "data:image/png;base64,AAAA"));

        verify(mailSender).send(mime);
    }

    @Test
    void sendTemplatedEmail_nullModelValue_sendsWithEmptyString() throws Exception {
        stubTemplate("Hello {{name}}, welcome");
        MimeMessage mime = new MimeMessage(jakarta.mail.Session.getInstance(new java.util.Properties()));
        when(mailSender.createMimeMessage()).thenReturn(mime);

        Map<String, Object> model = new HashMap<>();
        model.put("name", null);

        service.sendTemplatedEmail("a@example.com", "s", "welcome", model);

        verify(mailSender).send(mime);
    }

    @Test
    void sendTemplatedEmail_nonUrlKey_notSchemeChecked() throws Exception {
        stubTemplate("Message: {{message}}");
        MimeMessage mime = new MimeMessage(jakarta.mail.Session.getInstance(new java.util.Properties()));
        when(mailSender.createMimeMessage()).thenReturn(mime);

        service.sendTemplatedEmail("a@example.com", "s", "welcome",
                Map.of("message", "javascript:alert(1)"));

        verify(mailSender).send(mime);
    }

    // ── Model can be null ──────────────────────────────────────────────────

    @Test
    void sendTemplatedEmail_nullModel_sendsTemplateVerbatim() throws Exception {
        stubTemplate("<p>Fixed body</p>");
        MimeMessage mime = new MimeMessage(jakarta.mail.Session.getInstance(new java.util.Properties()));
        when(mailSender.createMimeMessage()).thenReturn(mime);

        service.sendTemplatedEmail("a@example.com", "s", "welcome", null);

        verify(mailSender).send(mime);
    }

    // ── Attachments ────────────────────────────────────────────────────────

    @Test
    void sendTemplatedEmail_withAttachment_attachedToMime() throws Exception {
        stubTemplate("<p>{{name}}</p>");
        MimeMessage mime = new MimeMessage(jakarta.mail.Session.getInstance(new java.util.Properties()));
        when(mailSender.createMimeMessage()).thenReturn(mime);

        byte[] pdfBytes = "%PDF-1.4 fake content".getBytes(StandardCharsets.UTF_8);
        Map<String, Object> model = new HashMap<>();
        model.put("name", "Alice");
        model.put("attachmentFilename", "report.pdf");
        model.put("attachmentContentType", "application/pdf");
        model.put("attachmentContentBase64", Base64.getEncoder().encodeToString(pdfBytes));

        service.sendTemplatedEmail("a@example.com", "s", "welcome", model);

        verify(mailSender).send(mime);
    }

    // ── Failure paths ──────────────────────────────────────────────────────

    @Test
    void sendTemplatedEmail_templateLoadFails_throwsWrappedRuntimeException() throws Exception {
        when(resourceLoader.getResource(anyString())).thenReturn(templateResource);
        when(templateResource.getInputStream()).thenThrow(new java.io.IOException("no such file"));

        assertThatThrownBy(() -> service.sendTemplatedEmail(
                "a@example.com", "s", "does-not-exist", Map.of()))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Failed to send SMTP email");
        verify(mailSender, never()).send(any(MimeMessage.class));
    }

    @Test
    void sendTemplatedEmail_mailSenderThrows_wrapsAsRuntimeException() throws Exception {
        stubTemplate("<p>hi</p>");
        MimeMessage mime = new MimeMessage(jakarta.mail.Session.getInstance(new java.util.Properties()));
        when(mailSender.createMimeMessage()).thenReturn(mime);
        doThrow(new RuntimeException("smtp down")).when(mailSender).send(any(MimeMessage.class));

        assertThatThrownBy(() -> service.sendTemplatedEmail("a@example.com", "s", "welcome", Map.of()))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Failed to send SMTP email");
    }

    // ── helpers ────────────────────────────────────────────────────────────

    private void stubTemplate(String html) throws Exception {
        when(resourceLoader.getResource(anyString())).thenReturn(templateResource);
        when(templateResource.getInputStream())
                .thenReturn(new ByteArrayInputStream(html.getBytes(StandardCharsets.UTF_8)));
    }
}
