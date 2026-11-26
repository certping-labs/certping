// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.notification;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.audit.OrganizationAuditRecorder;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.QueryTimeoutException;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static com.certmanagement.constants.FeatureFlags.NOTIFICATION_PREFERENCES;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NotificationPreferenceServiceTest {

    private static final long ORG = 42L;
    private static final long OTHER_ORG = 43L;

    @Mock private FeatureFlagService featureFlags;
    @Mock private OrganizationRepository organizations;
    @Mock private OrganizationAuditRecorder organizationAudit;

    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    private NotificationPreferenceService preferences;

    @BeforeEach
    void setUp() {
        preferences = new NotificationPreferenceService(featureFlags, organizations, organizationAudit, meters);
    }

    @Test
    void aTurnedOffCategoryIsNotDeliveredWhileTheOrganizationMayUseSettings() {
        when(featureFlags.isEnabled(NOTIFICATION_PREFERENCES, ORG)).thenReturn(true);
        when(organizations.findMutedNotificationCategories(ORG)).thenReturn(Optional.of("CERTIFICATE_ACTIVITY,REPORTS"));

        assertThat(preferences.allows(ORG, "CERT_RENEWAL_SUCCESS")).isFalse();
        assertThat(preferences.allows(ORG, "IOT_ACTIVITY_DIGEST")).isFalse();
        assertThat(preferences.allows(ORG, "DOMAIN_RENEWAL_SUCCESS")).isTrue();
    }

    @Test
    void savedChoicesAreIgnoredWhileNotificationSettingsAreOff() {
        when(featureFlags.isEnabled(NOTIFICATION_PREFERENCES, ORG)).thenReturn(false);

        assertThat(preferences.allows(ORG, "CERT_RENEWAL_SUCCESS")).isTrue();
        verify(organizations, never()).findMutedNotificationCategories(anyLong());
    }

    @Test
    void anActionOutsideEveryCategoryIsAllowedWithoutAnyRead() {
        assertThat(preferences.allows(ORG, "CERT_RENEWAL_FAILED")).isTrue();
        assertThat(preferences.allows(ORG, "RESET_PASSWORD")).isTrue();
        assertThat(preferences.allows(ORG, null)).isTrue();
        verifyNoInteractions(featureFlags, organizations);
    }

    @Test
    void oneOrganizationsChoiceNeverDecidesAnothers() {
        when(featureFlags.isEnabled(NOTIFICATION_PREFERENCES, ORG)).thenReturn(true);
        when(featureFlags.isEnabled(NOTIFICATION_PREFERENCES, OTHER_ORG)).thenReturn(true);
        when(organizations.findMutedNotificationCategories(ORG)).thenReturn(Optional.of("CERTIFICATE_ACTIVITY"));
        when(organizations.findMutedNotificationCategories(OTHER_ORG)).thenReturn(Optional.of(""));

        assertThat(preferences.allows(ORG, "CERT_ISSUANCE_SUCCESS")).isFalse();
        assertThat(preferences.allows(OTHER_ORG, "CERT_ISSUANCE_SUCCESS")).isTrue();
    }

    @Test
    void aDeletedOrUnknownOrganizationAndANameNoLongerACategoryAreDelivered() {
        when(featureFlags.isEnabled(NOTIFICATION_PREFERENCES, ORG)).thenReturn(true);
        when(organizations.findMutedNotificationCategories(ORG)).thenReturn(Optional.empty(), Optional.of("RETIRED"));

        assertThat(preferences.allows(ORG, "CERT_ISSUANCE_SUCCESS")).isTrue();
        assertThat(preferences.allows(ORG, "CERT_ISSUANCE_SUCCESS")).isTrue();
    }

    @Test
    void anUnreadableSettingOrFlagDeliversAndIsCounted() {
        when(featureFlags.isEnabled(NOTIFICATION_PREFERENCES, ORG)).thenReturn(true);
        when(organizations.findMutedNotificationCategories(ORG)).thenThrow(new QueryTimeoutException("slow"));
        when(featureFlags.isEnabled(NOTIFICATION_PREFERENCES, OTHER_ORG)).thenThrow(new IllegalStateException("down"));

        assertThat(preferences.allows(ORG, "CERT_ISSUANCE_SUCCESS")).isTrue();
        assertThat(preferences.allows(OTHER_ORG, "CERT_ISSUANCE_SUCCESS")).isTrue();
        assertThat(meters.counter("certping.notifications.preference_check_failed").count()).isEqualTo(2);
    }

    @Test
    void aSuppressedDeliveryIsCountedByChannelAndCategory() {
        preferences.recordSuppressed(ORG, "CERT_RENEWAL_SUCCESS", "integration");

        assertThat(meters.counter("certping.notifications.suppressed", "channel", "integration",
                "category", "CERTIFICATE_ACTIVITY").count()).isEqualTo(1);
    }

    @Test
    void readsTheCategoriesTurnedOff() {
        when(organizations.findMutedNotificationCategories(ORG)).thenReturn(Optional.of("REPORTS"));

        assertThat(preferences.muted(ORG)).containsExactly(NotificationCategory.REPORTS);
        verify(featureFlags).assertEnabled(NOTIFICATION_PREFERENCES, ORG);
    }

    @Test
    void readingAndChangingAreRefusedWithTheGenericCopyWhileSettingsAreOff() {
        doThrow(new FeatureDisabledException(NOTIFICATION_PREFERENCES))
                .when(featureFlags).assertEnabled(NOTIFICATION_PREFERENCES, ORG);

        assertThatThrownBy(() -> preferences.muted(ORG)).isInstanceOf(FeatureDisabledException.class)
                .hasMessage("Notification settings aren't available. Ask your CertPing administrator.");
        assertThatThrownBy(() -> preferences.replaceMuted(ORG, List.of("REPORTS")))
                .isInstanceOf(FeatureDisabledException.class);
        verifyNoInteractions(organizations, organizationAudit);
    }

    @Test
    void aChangeIsWrittenUnderTheRowLockInCatalogueOrderAndAudited() {
        when(organizations.lockMutedNotificationCategories(ORG)).thenReturn(Optional.of("REPORTS"));

        assertThat(preferences.replaceMuted(ORG, List.of("REPORTS", "CERTIFICATE_ACTIVITY")))
                .containsExactly(NotificationCategory.CERTIFICATE_ACTIVITY, NotificationCategory.REPORTS);

        verify(organizations).updateMutedNotificationCategories(ORG, "CERTIFICATE_ACTIVITY,REPORTS");
        verify(organizationAudit).notificationSettingsChanged(ORG, "REPORTS", "CERTIFICATE_ACTIVITY,REPORTS");
    }

    @Test
    void theSameAnswerTwiceWritesAndAuditsNothing() {
        when(organizations.lockMutedNotificationCategories(ORG)).thenReturn(Optional.of("CERTIFICATE_ACTIVITY"));

        preferences.replaceMuted(ORG, List.of("CERTIFICATE_ACTIVITY"));

        verify(organizations, never()).updateMutedNotificationCategories(anyLong(), anyString());
        verify(organizationAudit, never()).notificationSettingsChanged(anyLong(), any(), any());
    }

    @Test
    void turningEverythingBackOnStoresAnEmptyList() {
        String all = String.join(",", Arrays.stream(NotificationCategory.values()).map(Enum::name).toList());
        when(organizations.lockMutedNotificationCategories(ORG)).thenReturn(Optional.of(all));

        assertThat(preferences.replaceMuted(ORG, List.of())).isEmpty();

        verify(organizations).updateMutedNotificationCategories(ORG, "");
        verify(organizationAudit).notificationSettingsChanged(ORG, all, "");
    }

    @Test
    void aMissingListAnUnknownOrARepeatedCategoryIsRefusedBeforeAnyRead() {
        assertThatThrownBy(() -> preferences.replaceMuted(ORG, null)).isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> preferences.replaceMuted(ORG, List.of("SECURITY")))
                .isInstanceOf(BadRequestException.class).hasMessage("Unknown notification category");
        assertThatThrownBy(() -> preferences.replaceMuted(ORG, List.of("REPORTS", "REPORTS")))
                .isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> preferences.replaceMuted(ORG, java.util.Arrays.asList("REPORTS", null)))
                .isInstanceOf(BadRequestException.class);
        verifyNoInteractions(organizations, organizationAudit);
    }

    @Test
    void aDeletedOrUnknownOrganizationIsNotFound() {
        when(organizations.findMutedNotificationCategories(ORG)).thenReturn(Optional.empty());
        when(organizations.lockMutedNotificationCategories(ORG)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> preferences.muted(ORG)).isInstanceOf(ResourceNotFoundException.class);
        assertThatThrownBy(() -> preferences.replaceMuted(ORG, List.of())).isInstanceOf(ResourceNotFoundException.class);
        verify(organizations, never()).updateMutedNotificationCategories(anyLong(), anyString());
    }
}
