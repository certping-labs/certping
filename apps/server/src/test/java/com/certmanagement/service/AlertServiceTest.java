// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.entity.AlertEntity;
import com.certmanagement.enums.AlertTypeEnum;
import com.certmanagement.repository.AlertRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AlertServiceTest {

    @Mock
    private AlertRepository alertRepository;

    @Mock
    private com.certmanagement.service.audit.MonitoringAuditRecorder monitoringAudit;

    @InjectMocks
    private AlertService alertService;

    @Test
    void getAlerts_forOrganization_usesCreatedAtOrderedRepositoryMethod() {
        Long organizationId = 1L;
        when(alertRepository.findByOrganizationIdOrderByCreatedAtDesc(organizationId))
                .thenReturn(List.of(AlertEntity.builder().id(1L).organizationId(organizationId).alertType(AlertTypeEnum.CERTIFICATE_FAILURE).build()));

        var response = alertService.getAlerts(null, organizationId, null);

        assertThat(response.getAlerts()).hasSize(1);
        verify(alertRepository).findByOrganizationIdOrderByCreatedAtDesc(organizationId);
        assertThat(response.getAlerts().get(0).getAlertType()).isEqualTo(AlertTypeEnum.CERTIFICATE_FAILURE);
    }

    @Test
    void getAlerts_forUser_usesCreatedAtOrderedRepositoryMethod() {
        Integer userId = 123;
        when(alertRepository.findByUserIdOrderByCreatedAtDesc(userId))
                .thenReturn(List.of(AlertEntity.builder().id(2L).userId(userId).alertType(AlertTypeEnum.DEPLOYMENT_FAILURE).build()));

        var response = alertService.getAlerts(userId, null, null);

        assertThat(response.getAlerts()).hasSize(1);
        verify(alertRepository).findByUserIdOrderByCreatedAtDesc(userId);
        assertThat(response.getAlerts().get(0).getAlertType()).isEqualTo(AlertTypeEnum.DEPLOYMENT_FAILURE);
    }

    @Test
    void getAlerts_withTypeFilter_usesFilteredRepositoryMethod() {
        Long organizationId = 7L;
        when(alertRepository.findByOrganizationIdAndAlertTypeOrderByCreatedAtDesc(organizationId, AlertTypeEnum.CERTIFICATE_FAILURE))
                .thenReturn(List.of(AlertEntity.builder().id(3L).organizationId(organizationId).alertType(AlertTypeEnum.CERTIFICATE_FAILURE).build()));

        var response = alertService.getAlerts(null, organizationId, AlertTypeEnum.CERTIFICATE_FAILURE);

        assertThat(response.getAlerts()).hasSize(1);
        verify(alertRepository).findByOrganizationIdAndAlertTypeOrderByCreatedAtDesc(organizationId, AlertTypeEnum.CERTIFICATE_FAILURE);
    }

    @Test
    void markingAnAlertReadIsRecordedOnceAndAnUnchangedOneNotAtAll() {
        AlertEntity alert = AlertEntity.builder().id(5L).organizationId(1L).unread(true).build();
        when(alertRepository.findById(5L)).thenReturn(java.util.Optional.of(alert));
        when(alertRepository.save(alert)).thenReturn(alert);

        alertService.updateAlert(5L, false, 7, 1L);
        alertService.updateAlert(5L, false, 7, 1L);
        alertService.updateAlert(5L, null, 7, 1L);

        verify(monitoringAudit).alertMarked(alert, false);
        org.mockito.Mockito.verifyNoMoreInteractions(monitoringAudit);
    }

    @Test
    void anotherOrganizationsAlertAnswersAsNotFound() {
        AlertEntity alert = AlertEntity.builder().id(5L).organizationId(2L).unread(true).build();
        when(alertRepository.findById(5L)).thenReturn(java.util.Optional.of(alert));

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> alertService.updateAlert(5L, false, 7, 1L))
                .isInstanceOf(com.certmanagement.exception.ResourceNotFoundException.class)
                .hasMessage("Alert not found with id: 5");
        verify(alertRepository, org.mockito.Mockito.never()).save(alert);
    }
}
