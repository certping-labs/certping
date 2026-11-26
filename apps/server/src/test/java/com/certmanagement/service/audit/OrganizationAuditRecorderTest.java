// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditChange;
import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditVisibility;
import com.certmanagement.entity.Organization;
import com.certmanagement.security.GatewayRequestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/** The organization, data-retention and platform-setting events as they are written. */
class OrganizationAuditRecorderTest {

    private static final long ORG_ID = 42L;

    private final AuditRecorder recorder = mock(AuditRecorder.class);
    private final OrganizationAuditRecorder audit = new OrganizationAuditRecorder(recorder);

    @BeforeEach
    void asSuperAdmin() {
        GatewayRequestContext.set(1, null, "req-1", "ops@certping.test");
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("ops", null,
                List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN"))));
    }

    @AfterEach
    void clear() {
        GatewayRequestContext.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void aCreatedOrganizationHasTheRowInItsOwnTrailAsAStaffRow() {
        audit.organizationCreated(Organization.builder().id(ORG_ID).name("Acme Secret Project").build());

        AuditEventRow row = recorded();
        assertThat(row.event()).isEqualTo("organization.created");
        assertThat(row.summary()).isEqualTo("Created the organization");
        assertThat(row.organizationId()).isEqualTo(ORG_ID);
        assertThat(row.actorStaff()).isTrue();
        assertThat(row.toString()).as("the name is rendered live, never stored").doesNotContain("Acme Secret Project");
    }

    @Test
    void anUpdateKeepsTheAllowListedChangesAndARenameByFieldNameOnly() {
        audit.organizationUpdated(ORG_ID, true, "old.test", "new.test", true, false);

        AuditEventRow row = recorded();
        assertThat(row.event()).isEqualTo("organization.updated");
        assertThat(row.details().changes()).containsExactly(new AuditChange("name", null, null),
                new AuditChange("domain", "old.test", "new.test"), new AuditChange("active", "true", "false"));
    }

    @Test
    void deleted() {
        audit.organizationDeleted(ORG_ID);

        assertThat(recorded().summary()).isEqualTo("Deleted the organization");
    }

    @Test
    void purgedRecordsSayHowManyAndHowOld() {
        audit.recordsPurged(ORG_ID, 30, 12);

        AuditEventRow row = recorded();
        assertThat(row.event()).isEqualTo("data_retention.purged");
        assertThat(row.summary()).isEqualTo("Permanently deleted 12 records removed more than 30 days ago");
    }

    @Test
    void aRetentionChangeKeepsBeforeAndAfter() {
        audit.retentionChanged(ORG_ID, null, 14);

        AuditEventRow row = recorded();
        assertThat(row.event()).isEqualTo("data_retention.changed");
        assertThat(row.summary()).isEqualTo("Changed how long removed records are kept");
        assertThat(row.details().changes()).containsExactly(new AuditChange("retentionDays", null, "14"));
    }

    @Test
    void aNotificationSettingsChangeIsTheOrganizationsRowWithBeforeAndAfter() {
        audit.notificationSettingsChanged(ORG_ID, "", "CERTIFICATE_ACTIVITY,REPORTS");

        AuditEventRow row = recorded();
        assertThat(row.event()).isEqualTo("notification_settings.changed");
        assertThat(row.visibility()).isEqualTo(AuditVisibility.CUSTOMER);
        assertThat(row.organizationId()).isEqualTo(ORG_ID);
        assertThat(row.summary()).isEqualTo("Changed which notifications are sent");
        assertThat(row.details().changes())
                .containsExactly(new AuditChange("mutedCategories", "", "CERTIFICATE_ACTIVITY,REPORTS"));
    }

    @Test
    void aPlatformSettingIsAnInternalRow() {
        audit.platformSettingChanged("soft_delete_retention_days", "30", "60");

        AuditEventRow row = recorded();
        assertThat(row.event()).isEqualTo("platform_setting.changed");
        assertThat(row.visibility()).isEqualTo(AuditVisibility.INTERNAL);
        assertThat(row.organizationId()).isNull();
        assertThat(row.summary()).isEqualTo("Changed the platform setting 'soft_delete_retention_days'");
        assertThat(row.details().changes()).containsExactly(new AuditChange("value", "30", "60"));
    }

    private AuditEventRow recorded() {
        ArgumentCaptor<AuditEventRow> row = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder).record(row.capture());
        return row.getValue();
    }
}
