// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.config.SenderAddresses;
import jakarta.annotation.PostConstruct;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.Transport;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.util.FileCopyUtils;

import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import com.certping.notification.utils.RequestContextLogger;
import com.certping.notification.utils.SafeFailure;
import com.certping.notification.interceptor.RequestContextInterceptor;
import org.slf4j.Logger;

@Slf4j
@Service
@ConditionalOnProperty(name = "email.provider", havingValue = "smtp", matchIfMissing = false)
@RequiredArgsConstructor
public class SmtpEmailService implements EmailProvider {

    private static final ScheduledExecutorService SEND_DEADLINES = Executors.newSingleThreadScheduledExecutor(
            runnable -> { Thread thread = new Thread(runnable, "smtp-send-deadline"); thread.setDaemon(true); return thread; });
    
    private static final Set<String> ALLOWED_URL_SCHEMES = Set.of("http://", "https://", "mailto:");
    
    private final JavaMailSender mailSender;
    private final ResourceLoader resourceLoader;
    private final DeliveryTimeouts deliveryTimeouts;
    
    @Value("${email.sender-address:}")
    private String senderAddress;

    @Value("${email.frontend-base-url:}")
    private String frontendBaseUrl;

    @Value("${spring.mail.host:}")
    private String mailHost;

    /**
     * Uses EMAIL_FROM, or no-reply at the host of CERTPING_URL when it is unset. With SMTP configured
     * and neither available, startup fails rather than sending mail from an address nobody chose.
     */
    @PostConstruct
    void resolveSenderAddress() {
        senderAddress = SenderAddresses.resolve(senderAddress, frontendBaseUrl);
        if (senderAddress == null && mailHost != null && !mailHost.isBlank()) {
            throw new IllegalStateException("EMAIL_FROM is not set and CERTPING_URL has no host to derive it from."
                    + " Set EMAIL_FROM to the address notification email is sent from, for example"
                    + " certping@your-domain.example.");
        }
        if (senderAddress == null) {
            log.warn("No sender address: set EMAIL_FROM (or CERTPING_URL) before configuring SMTP");
        }
    }

    @Override
    public void sendTemplatedEmail(String to, String subject, String templateName, Map<String, Object> model) {
        sendTemplatedEmail(to, List.of(), subject, templateName, model);
    }

    @Override
    public void sendTemplatedEmail(String to, List<String> cc, String subject, String templateName,
                                   Map<String, Object> model) {
        try {
            String htmlContent = render(templateName, model);

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            
            helper.setFrom(senderAddress);
            helper.setTo(to);
            if (!cc.isEmpty()) {
                helper.setCc(cc.toArray(String[]::new));
            }
            helper.setSubject(subject);
            helper.setText(htmlContent, true);

            attachIfPresent(helper, model);

            sendWithDeadline(message);
            contextLogger().info("SMTP email sent successfully");
        } catch (Exception e) {
            contextLogger().error("Failed to send SMTP email: {}", SafeFailure.describe(e));
            if (e instanceof EmailSendDeadlineException deadline) {
                throw deadline;
            }
            throw new RuntimeException("Failed to send SMTP email", e);
        }
    }

    private void sendWithDeadline(MimeMessage message) throws Exception {
        if (!(mailSender instanceof JavaMailSenderImpl sender)) {
            mailSender.send(message);
            return;
        }
        Transport transport = sender.getSession().getTransport(sender.getProtocol());
        AtomicBoolean expired = new AtomicBoolean();
        long deadlineMillis = Math.max(1, deliveryTimeouts.sendBudget().minusSeconds(5).toMillis());
        ScheduledFuture<?> deadline = SEND_DEADLINES.schedule(() -> {
            expired.set(true);
            Thread.startVirtualThread(() -> {
                try {
                    transport.close();
                } catch (Exception closeFailure) {
                    log.warn("Could not close SMTP transport at send deadline", closeFailure);
                }
            });
        }, deadlineMillis, TimeUnit.MILLISECONDS);
        try {
            message.saveChanges();
            transport.connect(sender.getHost(), sender.getPort(), sender.getUsername(), sender.getPassword());
            if (expired.get()) {
                throw new EmailSendDeadlineException("SMTP send deadline elapsed during connection");
            }
            transport.sendMessage(message, message.getAllRecipients());
            if (expired.get()) {
                throw new EmailSendDeadlineException("SMTP send deadline elapsed during delivery");
            }
        } finally {
            deadline.cancel(false);
            try {
                transport.close();
            } catch (Exception closeFailure) {
                log.warn("Could not close SMTP transport after delivery", closeFailure);
            }
        }
    }
    
    /**
     * Attach a base64 file from the notification model, if the publisher included one.
     * Best-effort: a malformed attachment is logged and skipped so the email body
     * is still delivered.
     */
    private void attachIfPresent(MimeMessageHelper helper, Map<String, Object> model) {
        try {
            OutboundAttachment attachment = OutboundAttachment.fromModel(model);
            if (attachment == null) {
                return;
            }
            helper.addAttachment(
                    attachment.filename(),
                    new ByteArrayResource(attachment.content()),
                    attachment.contentType());
            contextLogger().info("Attached '{}' ({} bytes) to SMTP email",
                    attachment.filename(), attachment.content().length);
        } catch (Exception e) {
            contextLogger().error("Failed to attach file to SMTP email — sending body only: {}", e.getMessage(), e);
        }
    }

    /** The template with every model placeholder filled, each value through the sanitizer. */
    String render(String templateName, Map<String, Object> model) {
        String htmlContent = loadTemplate(templateName);
        if (model != null) {
            for (Map.Entry<String, Object> entry : model.entrySet()) {
                String placeholder = "{{" + entry.getKey() + "}}";
                htmlContent = htmlContent.replace(placeholder, sanitizeTemplateValue(entry.getKey(), entry.getValue()));
            }
        }
        return htmlContent;
    }

    private String loadTemplate(String templateName) {
        try {
            String templatePath = String.format("classpath:templates/%s.html", templateName);
            Resource resource = resourceLoader.getResource(templatePath);
            
            try (Reader reader = new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8)) {
                return FileCopyUtils.copyToString(reader);
            }
        } catch (Exception e) {
            contextLogger().error("Failed to load email template: {}", templateName, e);
            throw new RuntimeException("Failed to load email template: " + templateName, e);
        }
    }

    /**
     * Sanitize template values to prevent XSS via javascript: URIs in href attributes.
     * URL-type values (keys containing 'Link', 'Url', 'url', 'link') are validated
     * to ensure they use allowed schemes (http://, https://, mailto:).
     */
    private String sanitizeTemplateValue(String key, Object value) {
        if (value == null) {
            return "";
        }
        String strValue = String.valueOf(value);
        String keyLower = key.toLowerCase();
        if (keyLower.contains("link") || keyLower.contains("url")) {
            String trimmed = strValue.trim().toLowerCase();
            boolean allowed = ALLOWED_URL_SCHEMES.stream().anyMatch(trimmed::startsWith);
            if (!allowed && !trimmed.startsWith("/")) {
                contextLogger().warn("Blocked potentially unsafe URL in template variable '{}': {}", key, strValue);
                return "#";
            }
        }
        return strValue;
    }

    /**
     * Creates a context-aware logger with request tracking IDs from the current request.
     */
    private Logger contextLogger() {
        return RequestContextLogger.getLogger(SmtpEmailService.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }
}
