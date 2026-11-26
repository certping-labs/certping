// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.azure.communication.email.EmailClient;
import com.azure.communication.email.EmailClientBuilder;
import com.azure.communication.email.models.EmailMessage;
import com.azure.communication.email.models.EmailSendResult;
import com.azure.core.util.polling.SyncPoller;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.fail;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class EmailServiceTest {

    @Mock
    private ResourceLoader resourceLoader;

    private EmailClient emailClient;
    private EmailService emailService;
    private MockedStatic<EmailClientBuilder> mockedClientBuilder;

    private final String senderAddress = "sender@example.com";

    @BeforeEach
    void setUp() {
        // Mock EmailClient and builder
        emailClient = mock(EmailClient.class);
        EmailClientBuilder builder = mock(EmailClientBuilder.class);
        when(builder.connectionString(anyString())).thenReturn(builder);
        when(builder.buildClient()).thenReturn(emailClient);

        // Mock the poller that is returned by beginSend()
        @SuppressWarnings("unchecked")
        SyncPoller<EmailSendResult, EmailSendResult> syncPoller = mock(SyncPoller.class);
        when(emailClient.beginSend(any(EmailMessage.class))).thenReturn(syncPoller);

        // Instantiate the service under test
        // Use a syntactically valid fake connection string for testing
        String fakeConnectionString = "endpoint=https://example.com;accesskey=fakekey";
        emailService = new EmailService(fakeConnectionString, senderAddress, resourceLoader);
        // Inject the mock EmailClient into the EmailService instance using reflection
        try {
            java.lang.reflect.Field clientField = EmailService.class.getDeclaredField("emailClient");
            clientField.setAccessible(true);
            clientField.set(emailService, emailClient);
        } catch (Exception e) {
            throw new RuntimeException("Failed to inject mock EmailClient", e);
        }
    }

    @AfterEach
    void tearDown() {
        // Close the static mock after each test
        if (mockedClientBuilder != null) {
            mockedClientBuilder.close();
        }
    }

    @Test
    void whenSendTemplatedEmail_thenEmailIsSentSuccessfully() throws Exception {
        // Fully mock all dependencies to avoid RuntimeException
        Resource resource = mock(Resource.class);
        when(resourceLoader.getResource(anyString())).thenReturn(resource);
        when(resource.getInputStream()).thenReturn(new java.io.ByteArrayInputStream("Hello, {{name}}!".getBytes()));

        // Mock the email client to return a mock poller
        SyncPoller<EmailSendResult, EmailSendResult> syncPoller = mock(SyncPoller.class);
        when(emailClient.beginSend(any(EmailMessage.class))).thenReturn(syncPoller);

        // Arrange
        String to = "recipient@example.com";
        String subject = "Test Subject";
        String templateName = "test-template";
        Map<String, Object> model = new HashMap<>();
        model.put("name", "TestUser");

        // Act
        try {
            emailService.sendTemplatedEmail(to, subject, templateName, model);
        } catch (Exception e) {
            e.printStackTrace();
            fail("Exception thrown: " + e.getMessage());
        }

        // Assert
        ArgumentCaptor<EmailMessage> messageCaptor = ArgumentCaptor.forClass(EmailMessage.class);
        verify(emailClient).beginSend(messageCaptor.capture());
        EmailMessage capturedMessage = messageCaptor.getValue();
        assertEquals(senderAddress, capturedMessage.getSenderAddress());
        assertEquals(to, capturedMessage.getToRecipients().get(0).getAddress());
        assertEquals(subject, capturedMessage.getSubject());
        assertEquals("Hello, TestUser!", capturedMessage.getBodyHtml());
    }

    @Test
    void copiesRideOnTheSameAcsMessage() throws Exception {
        Resource resource = mock(Resource.class);
        when(resourceLoader.getResource(anyString())).thenReturn(resource);
        when(resource.getInputStream()).thenReturn(new java.io.ByteArrayInputStream("Hi".getBytes()));

        emailService.sendTemplatedEmail("attorney@law.test", java.util.List.of("legal@example.com"),
                "Subject", "test-template", new HashMap<>());

        ArgumentCaptor<EmailMessage> messageCaptor = ArgumentCaptor.forClass(EmailMessage.class);
        verify(emailClient).beginSend(messageCaptor.capture());
        EmailMessage message = messageCaptor.getValue();
        assertEquals("attorney@law.test", message.getToRecipients().get(0).getAddress());
        assertEquals(1, message.getCcRecipients().size());
        assertEquals("legal@example.com", message.getCcRecipients().get(0).getAddress());
    }

    // ── 429 rate-limit classification (our recent redesign) ────────────────

    @Test
    void whenAcs429WithRetryAfterHeader_throwsRetryableExceptionWithHeaderDelay() throws Exception {
        Resource resource = mock(Resource.class);
        when(resourceLoader.getResource(anyString())).thenReturn(resource);
        when(resource.getInputStream()).thenReturn(new java.io.ByteArrayInputStream("body".getBytes()));

        com.azure.core.http.HttpResponse httpResp = mock(com.azure.core.http.HttpResponse.class);
        when(httpResp.getStatusCode()).thenReturn(429);
        com.azure.core.http.HttpHeaders headers = new com.azure.core.http.HttpHeaders();
        headers.set(com.azure.core.http.HttpHeaderName.RETRY_AFTER, "3703");
        when(httpResp.getHeaders()).thenReturn(headers);

        com.azure.core.exception.HttpResponseException hre =
                new com.azure.core.exception.HttpResponseException("throttled", httpResp);
        when(emailClient.beginSend(any(EmailMessage.class))).thenThrow(hre);

        com.certping.notification.exception.RetryableNotificationException thrown =
                assertThrows(com.certping.notification.exception.RetryableNotificationException.class,
                        () -> emailService.sendTemplatedEmail("to@example.com", "s", "t", new HashMap<>()));

        assertEquals("ACS_RATE_LIMITED", thrown.getReasonCode());
        assertEquals(java.time.Duration.ofSeconds(3703), thrown.getRetryAfter());
    }

    @Test
    void whenAcs429WithBodyDelayNoHeader_parsesFromBody() throws Exception {
        Resource resource = mock(Resource.class);
        when(resourceLoader.getResource(anyString())).thenReturn(resource);
        when(resource.getInputStream()).thenReturn(new java.io.ByteArrayInputStream("body".getBytes()));

        com.azure.core.http.HttpResponse httpResp = mock(com.azure.core.http.HttpResponse.class);
        when(httpResp.getStatusCode()).thenReturn(429);
        when(httpResp.getHeaders()).thenReturn(new com.azure.core.http.HttpHeaders()); // empty

        com.azure.core.exception.HttpResponseException hre =
                new com.azure.core.exception.HttpResponseException(
                        "Please try again after 1200 seconds.", httpResp);
        when(emailClient.beginSend(any(EmailMessage.class))).thenThrow(hre);

        com.certping.notification.exception.RetryableNotificationException thrown =
                assertThrows(com.certping.notification.exception.RetryableNotificationException.class,
                        () -> emailService.sendTemplatedEmail("to@example.com", "s", "t", new HashMap<>()));

        assertEquals(java.time.Duration.ofSeconds(1200), thrown.getRetryAfter());
    }

    @Test
    void whenAcs429WithNoHeaderOrBody_defaultsToSixtySeconds() throws Exception {
        Resource resource = mock(Resource.class);
        when(resourceLoader.getResource(anyString())).thenReturn(resource);
        when(resource.getInputStream()).thenReturn(new java.io.ByteArrayInputStream("body".getBytes()));

        com.azure.core.http.HttpResponse httpResp = mock(com.azure.core.http.HttpResponse.class);
        when(httpResp.getStatusCode()).thenReturn(429);
        when(httpResp.getHeaders()).thenReturn(new com.azure.core.http.HttpHeaders());

        com.azure.core.exception.HttpResponseException hre =
                new com.azure.core.exception.HttpResponseException("throttled (no hint)", httpResp);
        when(emailClient.beginSend(any(EmailMessage.class))).thenThrow(hre);

        com.certping.notification.exception.RetryableNotificationException thrown =
                assertThrows(com.certping.notification.exception.RetryableNotificationException.class,
                        () -> emailService.sendTemplatedEmail("to@example.com", "s", "t", new HashMap<>()));

        assertEquals(java.time.Duration.ofSeconds(60), thrown.getRetryAfter());
    }

    @Test
    void whenAcs503_classifiedAsAcsUnavailable() throws Exception {
        Resource resource = mock(Resource.class);
        when(resourceLoader.getResource(anyString())).thenReturn(resource);
        when(resource.getInputStream()).thenReturn(new java.io.ByteArrayInputStream("body".getBytes()));

        com.azure.core.http.HttpResponse httpResp = mock(com.azure.core.http.HttpResponse.class);
        when(httpResp.getStatusCode()).thenReturn(503);
        when(httpResp.getHeaders()).thenReturn(new com.azure.core.http.HttpHeaders());

        com.azure.core.exception.HttpResponseException hre =
                new com.azure.core.exception.HttpResponseException("unavailable", httpResp);
        when(emailClient.beginSend(any(EmailMessage.class))).thenThrow(hre);

        com.certping.notification.exception.RetryableNotificationException thrown =
                assertThrows(com.certping.notification.exception.RetryableNotificationException.class,
                        () -> emailService.sendTemplatedEmail("to@example.com", "s", "t", new HashMap<>()));

        assertEquals("ACS_UNAVAILABLE", thrown.getReasonCode());
    }

    @Test
    void whenAcs400_notRetryable_wrappedAsRuntimeException() throws Exception {
        // Non-throttle 4xx (e.g. malformed request) is NOT retryable.
        Resource resource = mock(Resource.class);
        when(resourceLoader.getResource(anyString())).thenReturn(resource);
        when(resource.getInputStream()).thenReturn(new java.io.ByteArrayInputStream("body".getBytes()));

        com.azure.core.http.HttpResponse httpResp = mock(com.azure.core.http.HttpResponse.class);
        when(httpResp.getStatusCode()).thenReturn(400);
        when(httpResp.getHeaders()).thenReturn(new com.azure.core.http.HttpHeaders());

        com.azure.core.exception.HttpResponseException hre =
                new com.azure.core.exception.HttpResponseException("bad request", httpResp);
        when(emailClient.beginSend(any(EmailMessage.class))).thenThrow(hre);

        RuntimeException thrown = assertThrows(RuntimeException.class,
                () -> emailService.sendTemplatedEmail("to@example.com", "s", "t", new HashMap<>()));

        assertEquals("Failed to send template email", thrown.getMessage());
    }

    @Test
    void whenRetryAfterHeaderIsNonNumeric_fallsBackToDefault() throws Exception {
        Resource resource = mock(Resource.class);
        when(resourceLoader.getResource(anyString())).thenReturn(resource);
        when(resource.getInputStream()).thenReturn(new java.io.ByteArrayInputStream("body".getBytes()));

        com.azure.core.http.HttpResponse httpResp = mock(com.azure.core.http.HttpResponse.class);
        when(httpResp.getStatusCode()).thenReturn(429);
        com.azure.core.http.HttpHeaders headers = new com.azure.core.http.HttpHeaders();
        headers.set(com.azure.core.http.HttpHeaderName.RETRY_AFTER, "Wed, 21 Oct 2015 07:28:00 GMT");
        when(httpResp.getHeaders()).thenReturn(headers);

        com.azure.core.exception.HttpResponseException hre =
                new com.azure.core.exception.HttpResponseException("throttled", httpResp);
        when(emailClient.beginSend(any(EmailMessage.class))).thenThrow(hre);

        com.certping.notification.exception.RetryableNotificationException thrown =
                assertThrows(com.certping.notification.exception.RetryableNotificationException.class,
                        () -> emailService.sendTemplatedEmail("to@example.com", "s", "t", new HashMap<>()));

        // Non-numeric → falls through to default 60s.
        assertEquals(java.time.Duration.ofSeconds(60), thrown.getRetryAfter());
    }

    @Test
    void whenRetryAfterHeaderIsZero_treatedAsMissing() throws Exception {
        Resource resource = mock(Resource.class);
        when(resourceLoader.getResource(anyString())).thenReturn(resource);
        when(resource.getInputStream()).thenReturn(new java.io.ByteArrayInputStream("body".getBytes()));

        com.azure.core.http.HttpResponse httpResp = mock(com.azure.core.http.HttpResponse.class);
        when(httpResp.getStatusCode()).thenReturn(429);
        com.azure.core.http.HttpHeaders headers = new com.azure.core.http.HttpHeaders();
        headers.set(com.azure.core.http.HttpHeaderName.RETRY_AFTER, "0");
        when(httpResp.getHeaders()).thenReturn(headers);

        com.azure.core.exception.HttpResponseException hre =
                new com.azure.core.exception.HttpResponseException("throttled", httpResp);
        when(emailClient.beginSend(any(EmailMessage.class))).thenThrow(hre);

        com.certping.notification.exception.RetryableNotificationException thrown =
                assertThrows(com.certping.notification.exception.RetryableNotificationException.class,
                        () -> emailService.sendTemplatedEmail("to@example.com", "s", "t", new HashMap<>()));

        assertEquals(java.time.Duration.ofSeconds(60), thrown.getRetryAfter());
    }

    // ── URL sanitization branches ──────────────────────────────────────────

    @Test
    void whenUrlKeyHasJavascriptScheme_replacedWithHash() throws Exception {
        Resource resource = mock(Resource.class);
        when(resourceLoader.getResource(anyString())).thenReturn(resource);
        when(resource.getInputStream()).thenReturn(new java.io.ByteArrayInputStream(
                "<a href=\"{{ctaLink}}\">click</a>".getBytes()));

        Map<String, Object> model = new HashMap<>();
        model.put("ctaLink", "javascript:alert(1)");
        emailService.sendTemplatedEmail("to@example.com", "s", "t", model);

        ArgumentCaptor<EmailMessage> captor = ArgumentCaptor.forClass(EmailMessage.class);
        verify(emailClient).beginSend(captor.capture());
        assertEquals("<a href=\"#\">click</a>", captor.getValue().getBodyHtml());
    }

    @Test
    void whenUrlKeyHasDataScheme_replacedWithHash() throws Exception {
        Resource resource = mock(Resource.class);
        when(resourceLoader.getResource(anyString())).thenReturn(resource);
        when(resource.getInputStream()).thenReturn(new java.io.ByteArrayInputStream(
                "<img src=\"{{logoUrl}}\">".getBytes()));

        Map<String, Object> model = new HashMap<>();
        model.put("logoUrl", "data:image/png;base64,AAAA");
        emailService.sendTemplatedEmail("to@example.com", "s", "t", model);

        ArgumentCaptor<EmailMessage> captor = ArgumentCaptor.forClass(EmailMessage.class);
        verify(emailClient).beginSend(captor.capture());
        assertEquals("<img src=\"#\">", captor.getValue().getBodyHtml());
    }

    @Test
    void whenUrlKeyHasBareDomain_allowedThrough() throws Exception {
        Resource resource = mock(Resource.class);
        when(resourceLoader.getResource(anyString())).thenReturn(resource);
        when(resource.getInputStream()).thenReturn(new java.io.ByteArrayInputStream(
                "<a href=\"{{ctaUrl}}\">link</a>".getBytes()));

        Map<String, Object> model = new HashMap<>();
        model.put("ctaUrl", "example.org"); // bare domain — allowed
        emailService.sendTemplatedEmail("to@example.com", "s", "t", model);

        ArgumentCaptor<EmailMessage> captor = ArgumentCaptor.forClass(EmailMessage.class);
        verify(emailClient).beginSend(captor.capture());
        assertEquals("<a href=\"example.org\">link</a>", captor.getValue().getBodyHtml());
    }

    @Test
    void whenModelValueIsNull_replacedWithEmpty() throws Exception {
        Resource resource = mock(Resource.class);
        when(resourceLoader.getResource(anyString())).thenReturn(resource);
        when(resource.getInputStream()).thenReturn(new java.io.ByteArrayInputStream(
                "Hi {{name}}!".getBytes()));

        Map<String, Object> model = new HashMap<>();
        model.put("name", null);
        emailService.sendTemplatedEmail("to@example.com", "s", "t", model);

        ArgumentCaptor<EmailMessage> captor = ArgumentCaptor.forClass(EmailMessage.class);
        verify(emailClient).beginSend(captor.capture());
        assertEquals("Hi !", captor.getValue().getBodyHtml());
    }

    @Test
    void whenModelIsNull_stillSends() throws Exception {
        Resource resource = mock(Resource.class);
        when(resourceLoader.getResource(anyString())).thenReturn(resource);
        when(resource.getInputStream()).thenReturn(new java.io.ByteArrayInputStream(
                "<p>fixed</p>".getBytes()));

        emailService.sendTemplatedEmail("to@example.com", "s", "t", null);

        verify(emailClient).beginSend(any(EmailMessage.class));
    }

    @Test
    void whenTemplateNotFound_thenThrowRuntimeException() {
        // Arrange
        String to = "recipient@example.com";
        String subject = "Test Subject";
        String templateName = "non-existent-template";
        Map<String, Object> model = new HashMap<>();

        doThrow(new RuntimeException("Template not found")).when(resourceLoader).getResource(anyString());

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            emailService.sendTemplatedEmail(to, subject, templateName, model);
        });

        assertEquals("Failed to send template email", exception.getMessage());
    }
}
