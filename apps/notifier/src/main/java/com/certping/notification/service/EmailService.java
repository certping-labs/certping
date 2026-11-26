// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.azure.communication.email.EmailClient;
import com.azure.communication.email.EmailClientBuilder;
import com.azure.communication.email.models.EmailAttachment;
import com.azure.communication.email.models.EmailMessage;
import com.azure.core.exception.HttpResponseException;
import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.policy.FixedDelay;
import com.azure.core.http.policy.RetryPolicy;
import com.azure.core.util.HttpClientOptions;
import com.azure.core.util.BinaryData;
import com.certping.notification.exception.RetryableNotificationException;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import com.certping.notification.utils.RequestContextLogger;
import com.certping.notification.utils.SafeFailure;
import com.certping.notification.interceptor.RequestContextInterceptor;
import org.slf4j.Logger;

@Slf4j
@Service
@ConditionalOnProperty(name = "email.provider", havingValue = "acs", matchIfMissing = false)
public class EmailService implements EmailProvider {
    private final EmailClient emailClient;
    private final ResourceLoader resourceLoader;
    private final String senderAddress;
    
    EmailService(String connectionString, String senderAddress, ResourceLoader resourceLoader) {
        this(connectionString, senderAddress, resourceLoader, Duration.ofSeconds(30));
    }

    /**
     * {@code timeout} bounds each phase of the submit (connect, write, response, read), so one send
     * ends well inside a deliver-once claim ({@link DeliveryTimeouts}).
     */
    @Autowired
    public EmailService(
            @Value("${azure.communication.connection-string:}") String connectionString,
            @Value("${email.sender-address}") String senderAddress,
            ResourceLoader resourceLoader,
            @Value("${notifier.delivery.acs-timeout:PT30S}") Duration timeout) {
        if (connectionString != null && !connectionString.isEmpty()) {
            // No SDK-level retries. The default RetryPolicy uses
            // ExponentialBackoff (3 attempts, 800ms → 8s) which does NOT
            // respect Retry-After — so on a 429 with a body hint like
            // "Please try again after 3703 seconds" the SDK burns 4 requests
            // in ~5 seconds, all of which count against the ACS per-minute
            // quota. Our queue-level ScheduledRetryService is the single
            // retry gate: it parses the body-embedded delay and reschedules
            // via ScheduledEnqueueTime, so we hit ACS once per attempt and
            // wait the full amount ACS actually asks for.
            this.emailClient = new EmailClientBuilder()
                .connectionString(connectionString)
                .retryPolicy(new RetryPolicy(new FixedDelay(0, Duration.ZERO)))
                .clientOptions(new HttpClientOptions().setConnectTimeout(timeout).setWriteTimeout(timeout)
                        .setResponseTimeout(timeout).setReadTimeout(timeout))
                .buildClient();
        } else {
            this.emailClient = null;
            contextLogger().warn("Azure Communication Service connection string not provided. Email sending will fail.");
        }
        this.resourceLoader = resourceLoader;
        this.senderAddress = senderAddress;
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

            EmailMessage message = new EmailMessage()
                    .setSenderAddress(senderAddress)
                    .setToRecipients(to)
                    .setSubject(subject)
                    .setBodyHtml(htmlContent);
            if (!cc.isEmpty()) {
                message.setCcRecipients(cc.toArray(String[]::new));
            }

            attachIfPresent(message, model);

            emailClient.beginSend(message);
            contextLogger().info("Template email sent successfully");
        } catch (HttpResponseException e) {
            // ACS surfaces rate limits + upstream backpressure as HTTP errors
            // on the submit path. Convert to a RetryableNotificationException
            // so the message handler can hand off to ScheduledRetryService and
            // hold the delivery for {@code Retry-After} seconds instead of
            // burning through {@code MaxDeliveryCount} in a busy-loop.
            RetryableNotificationException retryable = classifyAsRetryable(e);
            if (retryable != null) {
                contextLogger().warn(
                        "ACS submit rate-limited/throttled (code={}, retryAfterSec={}): {}",
                        retryable.getReasonCode(),
                        retryable.getRetryAfter().toSeconds(),
                        SafeFailure.describe(e));
                throw retryable;
            }
            contextLogger().error("Failed to send template email: {}", SafeFailure.describe(e));
            throw new RuntimeException("Failed to send template email", e);
        } catch (Exception e) {
            contextLogger().error("Failed to send template email: {}", SafeFailure.describe(e));
            throw new RuntimeException("Failed to send template email", e);
        }
    }

    /**
     * Classify an ACS SDK HTTP error as retryable if it looks like a rate limit
     * (429) or a transient server-side backpressure (503). The Retry-After
     * header is honoured when present; otherwise we default to 60s.
     * Returns null if the error is not retry-worthy (4xx auth/validation, 5xx
     * without a Retry-After hint, etc.).
     */
    private RetryableNotificationException classifyAsRetryable(HttpResponseException e) {
        int status = e.getResponse() != null ? e.getResponse().getStatusCode() : -1;
        if (status != 429 && status != 503) {
            return null;
        }
        String reasonCode = status == 429 ? "ACS_RATE_LIMITED" : "ACS_UNAVAILABLE";
        // Preference order: Retry-After header → "try again after N seconds"
        // from the ACS error body (they routinely put multi-hour delays here
        // for hourly quotas, e.g. PerSubscriptionPerHourLimitExceeded) → 60s
        // default. Defaulting to 60s on an hourly-quota 429 would just re-hit
        // the same limit ~60 times before the quota resets.
        Duration retryAfter = parseRetryAfter(e)
                .or(() -> parseRetryFromMessage(e.getMessage()))
                .orElse(Duration.ofSeconds(60));
        return new RetryableNotificationException(reasonCode, e.getMessage(), retryAfter, e);
    }

    private static final java.util.regex.Pattern TRY_AGAIN_AFTER =
            java.util.regex.Pattern.compile("try again after (\\d+) seconds",
                    java.util.regex.Pattern.CASE_INSENSITIVE);

    /**
     * Fallback delay parser for ACS Email throttle responses. The RFC says
     * Retry-After should be in the header, and ACS mostly does that — but the
     * hourly quota response ({@code PerSubscriptionPerHourLimitExceeded}) puts
     * the wait time only in the error message body, e.g.
     * {@code "Please try again after 3703 seconds."} Without this fallback
     * we'd default to 60s and immediately re-hit the same quota.
     */
    private Optional<Duration> parseRetryFromMessage(String message) {
        if (message == null || message.isBlank()) {
            return Optional.empty();
        }
        java.util.regex.Matcher m = TRY_AGAIN_AFTER.matcher(message);
        if (!m.find()) {
            return Optional.empty();
        }
        try {
            long seconds = Long.parseLong(m.group(1));
            if (seconds <= 0) {
                return Optional.empty();
            }
            return Optional.of(Duration.ofSeconds(seconds));
        } catch (NumberFormatException ignored) {
            return Optional.empty();
        }
    }

    private Optional<Duration> parseRetryAfter(HttpResponseException e) {
        if (e.getResponse() == null || e.getResponse().getHeaders() == null) {
            return Optional.empty();
        }
        String header = e.getResponse().getHeaders().getValue(HttpHeaderName.RETRY_AFTER);
        if (header == null || header.isBlank()) {
            return Optional.empty();
        }
        try {
            long seconds = Long.parseLong(header.trim());
            if (seconds <= 0) {
                return Optional.empty();
            }
            return Optional.of(Duration.ofSeconds(seconds));
        } catch (NumberFormatException nfe) {
            // ACS follows the RFC and returns Retry-After as delta-seconds,
            // not an HTTP-date. If we ever get a date, log and fall back to
            // the default so we don't crash on a well-formed but unexpected
            // response.
            contextLogger().warn("Non-numeric Retry-After from ACS: {}", header);
            return Optional.empty();
        }
    }
    
    /**
     * Attach a base64 file from the notification model, if the publisher included one.
     * Best-effort: a malformed attachment is logged and skipped so the email body
     * is still delivered.
     */
    private void attachIfPresent(EmailMessage message, Map<String, Object> model) {
        try {
            OutboundAttachment attachment = OutboundAttachment.fromModel(model);
            if (attachment == null) {
                return;
            }
            EmailAttachment acsAttachment = new EmailAttachment(
                    attachment.filename(),
                    attachment.contentType(),
                    BinaryData.fromBytes(attachment.content()));
            message.setAttachments(java.util.List.of(acsAttachment));
            contextLogger().info("Attached '{}' ({} bytes) to ACS email",
                    attachment.filename(), attachment.content().length);
        } catch (Exception e) {
            contextLogger().error("Failed to attach file to ACS email — sending body only: {}", e.getMessage(), e);
        }
    }

    /**
     * The template with every model placeholder filled, nested ones included (flattened by getModel),
     * each value through the sanitizer.
     */
    String render(String templateName, Map<String, Object> model) throws IOException {
        String htmlContent = loadTemplate(templateName);
        if (model != null) {
            for (Map.Entry<String, Object> entry : model.entrySet()) {
                String placeholder = "{{" + entry.getKey() + "}}";
                htmlContent = htmlContent.replace(placeholder, sanitizeTemplateValue(entry.getKey(), entry.getValue()));
            }
        }
        return htmlContent;
    }

    private String loadTemplate(String templateName) throws IOException {
        String templatePath = String.format("classpath:templates/%s.html", templateName);
        Resource resource = resourceLoader.getResource(templatePath);
        
        try (Reader reader = new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8)) {
            return FileCopyUtils.copyToString(reader);
        }
    }

    /**
     * Sanitize template values to prevent XSS via javascript: URIs in href attributes.
     * Only blocks values that use dangerous schemes (javascript:, data:, vbscript:).
     * Bare domains (e.g. "example.org") and plain text values are allowed through.
     */
    private String sanitizeTemplateValue(String key, Object value) {
        if (value == null) {
            return "";
        }
        String strValue = String.valueOf(value);
        String keyLower = key.toLowerCase();
        if (keyLower.contains("link") || keyLower.contains("url")) {
            String trimmed = strValue.trim().toLowerCase();
            // Only block dangerous schemes — allow bare domains, relative paths, and safe schemes
            if (trimmed.startsWith("javascript:") || trimmed.startsWith("data:") || trimmed.startsWith("vbscript:")) {
                contextLogger().warn("Blocked dangerous URL scheme in template variable '{}': {}", key, strValue);
                return "#";
            }
        }
        return strValue;
    }

    /**
     * Creates a context-aware logger with request tracking IDs from the current request.
     */
    private Logger contextLogger() {
        return RequestContextLogger.getLogger(EmailService.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }
}