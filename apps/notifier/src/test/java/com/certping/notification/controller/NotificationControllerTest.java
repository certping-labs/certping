// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.controller;

import com.certping.notification.model.NotificationEvent;
import com.certping.notification.model.NotificationRecord;
import com.certping.notification.model.NotificationStatus;
import com.certping.notification.repository.NotificationRepository;
import com.certping.notification.service.NotificationService;
import com.certping.notification.service.UndeliveredEmailService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NotificationControllerTest {

    @Mock
    private NotificationService notificationService;

    @Mock
    private NotificationRepository notificationRepository;

    @Mock
    private UndeliveredEmailService undeliveredEmailService;

    @InjectMocks
    private NotificationController notificationController;

    @Test
    void replayRequiresTheConfiguredAdminToken() {
        ReflectionTestUtils.setField(notificationController, "replayToken", "secret-value");
        assertEquals(403, notificationController.replayUndelivered("incorrect").getStatusCode().value());
        verifyNoInteractions(undeliveredEmailService);

        when(undeliveredEmailService.replay()).thenReturn(2);
        ResponseEntity<Map<String, Object>> response = notificationController.replayUndelivered("secret-value");

        assertEquals(200, response.getStatusCode().value());
        assertEquals(2, response.getBody().get("replayed"));
        verify(undeliveredEmailService).replay();
    }

    @Test
    void processNotifications_shouldCallServiceAndReturnOk() {
        // Given
        List<NotificationEvent> events = Collections.singletonList(new NotificationEvent());

        // When
        ResponseEntity<String> response = notificationController.processNotifications(events);

        // Then
        verify(notificationService).processNotifications(events);
        assertEquals(ResponseEntity.ok("Notifications processed successfully"), response);
    }

    @Test
    void getNotifications_withOrganizationId_shouldReturnPagedOrganizationNotifications() {
        Long organizationId = 1L;
        NotificationRecord row = NotificationRecord.builder().id(1L).organizationId(organizationId).build();
        Page<NotificationRecord> page = new PageImpl<>(List.of(row), PageRequest.of(0, 20), 1);
        when(notificationRepository.findByOrganizationIdOrderByCreatedAtDesc(eq(organizationId), any(Pageable.class)))
                .thenReturn(page);

        ResponseEntity<Map<String, Object>> response = notificationController.getNotifications(
                null, organizationId.toString(), null, null, null);

        assertEquals(200, response.getStatusCode().value());
        assertEquals(true, response.getBody().get("success"));
        assertEquals(0, response.getBody().get("page"));
        assertEquals(20, response.getBody().get("size"));
        assertEquals(1L, response.getBody().get("totalElements"));
        assertEquals(1, response.getBody().get("totalPages"));
    }

    @Test
    void getNotifications_neverReturnsTheStoredPayload() {
        Long organizationId = 1L;
        NotificationRecord row = NotificationRecord.builder().id(1L).organizationId(organizationId)
                .templateName("reset-password").status(NotificationStatus.DELIVERED)
                .payloadJson("[{\"templateFields\":{\"resetLink\":\"https://x/reset-password?token=abc\"}}]").build();
        when(notificationRepository.findByOrganizationIdOrderByCreatedAtDesc(eq(organizationId), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(row), PageRequest.of(0, 20), 1));

        ResponseEntity<Map<String, Object>> response = notificationController.getNotifications(
                null, organizationId.toString(), null, null, null);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> data = (List<Map<String, Object>>) response.getBody().get("data");
        assertEquals(1, data.size());
        assertFalse(data.get(0).containsKey("payloadJson"));
        assertEquals("reset-password", data.get(0).get("templateName"));
        assertFalse(String.valueOf(data).contains("token="));
    }

    @Test
    void getNotifications_withOrganizationAndStatus_shouldReturnFilteredPage() {
        Long organizationId = 2L;
        Page<NotificationRecord> empty = new PageImpl<>(List.of(), PageRequest.of(0, 20), 0);
        when(notificationRepository.findByOrganizationIdAndStatusOrderByCreatedAtDesc(
                eq(organizationId), eq(NotificationStatus.DELIVERED), any(Pageable.class)))
                .thenReturn(empty);

        ResponseEntity<Map<String, Object>> response = notificationController.getNotifications(
                null, organizationId.toString(), "DELIVERED", null, null);

        assertEquals(200, response.getStatusCode().value());
        assertEquals(true, response.getBody().get("success"));
        assertEquals(0L, response.getBody().get("totalElements"));
    }

    @Test
    void getNotifications_appliesDefaultPageSizeWhenNotSupplied() {
        Long organizationId = 3L;
        when(notificationRepository.findByOrganizationIdOrderByCreatedAtDesc(eq(organizationId), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(), PageRequest.of(0, 20), 0));

        notificationController.getNotifications(null, organizationId.toString(), null, null, null);

        ArgumentCaptor<Pageable> captor = ArgumentCaptor.forClass(Pageable.class);
        verify(notificationRepository).findByOrganizationIdOrderByCreatedAtDesc(eq(organizationId), captor.capture());
        assertEquals(0, captor.getValue().getPageNumber());
        assertEquals(20, captor.getValue().getPageSize());
    }

    @Test
    void getNotifications_capsPageSizeAtMax() {
        Long organizationId = 4L;
        when(notificationRepository.findByOrganizationIdOrderByCreatedAtDesc(eq(organizationId), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(), PageRequest.of(0, 100), 0));

        notificationController.getNotifications(null, organizationId.toString(), null, 0, 5000);

        ArgumentCaptor<Pageable> captor = ArgumentCaptor.forClass(Pageable.class);
        verify(notificationRepository).findByOrganizationIdOrderByCreatedAtDesc(eq(organizationId), captor.capture());
        assertEquals(100, captor.getValue().getPageSize());
    }

    @Test
    void getNotifications_withoutOrganizationId_shouldReturnBadRequest() {
        ResponseEntity<Map<String, Object>> response = notificationController.getNotifications(null, null, null, null, null);

        assertEquals(400, response.getStatusCode().value());
        assertEquals(false, response.getBody().get("success"));
        assertTrue(response.getBody().get("message").toString().contains("organizationId is required"));
    }

    @Test
    void getNotifications_withInvalidOrganizationId_shouldReturnBadRequest() {
        ResponseEntity<Map<String, Object>> response = notificationController.getNotifications(null, "invalid-long", null, null, null);

        assertEquals(400, response.getStatusCode().value());
        assertEquals(false, response.getBody().get("success"));
    }
}
