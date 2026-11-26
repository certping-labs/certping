// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.security.GatewayRequestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * {@link AuditedRead} through real Spring proxies: a sensitive read is recorded once it returned, grouped to one
 * row per organization, actor, event and target every 15 minutes; a different target, actor or organization is a
 * new row at once, and so is the same read once the 15 minutes have passed. A refused or failed read records
 * nothing. A super admin's read of a customer's data is a staff row in that customer's trail.
 */
class AuditedReadAspectTest {

    private static final long ORG_ID = 7L;

    private AnnotationConfigApplicationContext context;
    private AuditRecorder recorder;
    private Endpoints endpoints;

    /** A clock the test moves. */
    static final class MovableClock extends Clock {
        private Instant now = Instant.parse("2026-10-07T10:00:00Z");

        void advance(Duration by) {
            now = now.plus(by);
        }

        @Override public ZoneId getZone() { return ZoneId.of("UTC"); }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }

    @Configuration
    @EnableMethodSecurity
    @EnableAspectJAutoProxy
    static class Wiring {
        @Bean
        @DependsOnDatabaseInitialization
        AuditRecorder auditRecorder() { return mock(AuditRecorder.class); }
        @Bean MovableClock clock() { return new MovableClock(); }
        @Bean AuditedReads auditedReads(AuditRecorder recorder, MovableClock clock) {
            return new AuditedReads(recorder, clock);
        }
        @Bean AuditedReadAspect auditedReadAspect(AuditedReads reads) { return new AuditedReadAspect(reads); }
        @Bean Endpoints endpoints() { return new Endpoints(); }
    }

    static class Endpoints {

        @PreAuthorize("hasRole('ORGANIZATION_ADMIN') or hasRole('SUPER_ADMIN')")
        @AuditedRead(value = AuditEventType.ACCESS_AGENT_CONNECTION_VIEWED, target = "#organizationId",
                organization = "#organizationId")
        public ResponseEntity<String> connectionString(Long organizationId) {
            return ResponseEntity.ok("https://agent.example.test/?token=s3cr3t");
        }

        @AuditedRead(AuditEventType.ACCESS_CBOM_DOWNLOADED)
        public void cbom(boolean fail) {
            if (fail) {
                throw new IllegalStateException("the stream broke");
            }
        }

        @AuditedRead(AuditEventType.ACCESS_AUDIT_LOG_VIEWED)
        public ResponseEntity<String> auditLog(int status) {
            return ResponseEntity.status(status).body("page");
        }
    }

    @BeforeEach
    void setUp() {
        context = new AnnotationConfigApplicationContext(Wiring.class);
        recorder = context.getBean(AuditRecorder.class);
        endpoints = context.getBean(Endpoints.class);
        reset(recorder);
        GatewayRequestContext.set(5, String.valueOf(ORG_ID), "req-1", null);
        as("ORGANIZATION_ADMIN");
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        GatewayRequestContext.clear();
        context.close();
    }

    @Test
    void manyReadsOfOneTargetWithinFifteenMinutesWriteOneRow() {
        for (int i = 0; i < 20; i++) {
            endpoints.connectionString(null);
            clock().advance(Duration.ofSeconds(40));
        }

        AuditEventRow row = onlyRow();
        assertThat(row.event()).isEqualTo("access.agent_connection_viewed");
        assertThat(row.category()).isEqualTo("ACCESS");
        assertThat(row.visibility()).isEqualTo(AuditVisibility.CUSTOMER);
        assertThat(row.organizationId()).isEqualTo(ORG_ID);
        assertThat(row.actorUserId()).isEqualTo(5);
        assertThat(row.summary()).isEqualTo("Viewed the agent's connection string");
        assertThat(row.toString()).as("what was read is never part of the row").doesNotContain("s3cr3t")
                .doesNotContain("agent.example.test");
    }

    @Test
    void theSameReadAfterFifteenMinutesIsANewRow() {
        endpoints.cbom(false);
        clock().advance(Duration.ofMinutes(14));
        endpoints.cbom(false);
        clock().advance(Duration.ofMinutes(2));
        endpoints.cbom(false);

        verify(recorder, times(2)).recordAsync(any());
    }

    @Test
    void aDifferentTargetActorOrOrganizationIsANewRowAtOnce() {
        GatewayRequestContext.set(1, null, "req-2", null);
        as("SUPER_ADMIN");
        endpoints.connectionString(40L);
        endpoints.connectionString(40L);
        endpoints.connectionString(41L);
        GatewayRequestContext.set(2, null, "req-3", null);
        endpoints.connectionString(40L);

        ArgumentCaptor<AuditEventRow> rows = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder, times(3)).recordAsync(rows.capture());
        assertThat(rows.getAllValues()).extracting(AuditEventRow::organizationId, AuditEventRow::resourceRef,
                AuditEventRow::actorUserId).containsExactly(org.assertj.core.groups.Tuple.tuple(40L, "40", 1),
                org.assertj.core.groups.Tuple.tuple(41L, "41", 1), org.assertj.core.groups.Tuple.tuple(40L, "40", 2));
        assertThat(rows.getAllValues()).allSatisfy(row -> {
            assertThat(row.actorStaff()).as("a super admin reading a customer's secret is a staff row").isTrue();
            assertThat(row.visibility()).isEqualTo(AuditVisibility.CUSTOMER);
        });
    }

    @Test
    void anOrganizationAdminCannotWriteIntoAnotherOrganizationsTrail() {
        endpoints.connectionString(99L);

        assertThat(onlyRow().organizationId()).isEqualTo(ORG_ID);
    }

    @Test
    void staffReadingNoOrganizationsDataLeaveAnInternalRow() {
        GatewayRequestContext.set(1, null, "req-4", null);
        as("SUPER_ADMIN");

        endpoints.auditLog(200);

        AuditEventRow row = onlyRow();
        assertThat(row.visibility()).isEqualTo(AuditVisibility.INTERNAL);
        assertThat(row.organizationId()).isNull();
    }

    @Test
    void aRefusedOrFailedReadRecordsNothing() {
        as("VIEWER");
        assertThatThrownBy(() -> endpoints.connectionString(null)).isInstanceOf(AccessDeniedException.class);
        as("ORGANIZATION_ADMIN");
        assertThatThrownBy(() -> endpoints.cbom(true)).isInstanceOf(IllegalStateException.class);
        endpoints.auditLog(404);
        endpoints.auditLog(503);

        verify(recorder, never()).recordAsync(any());
    }

    @Test
    void aRowThatCannotBeQueuedNeverFailsTheRead() {
        org.mockito.Mockito.doThrow(new IllegalStateException("queue closed")).when(recorder).recordAsync(any());

        assertThat(endpoints.auditLog(200).getBody()).isEqualTo("page");
    }

    private MovableClock clock() {
        return context.getBean(MovableClock.class);
    }

    private AuditEventRow onlyRow() {
        ArgumentCaptor<AuditEventRow> rows = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder).recordAsync(rows.capture());
        return rows.getValue();
    }

    private static void as(String role) {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("user", null,
                List.of(new SimpleGrantedAuthority("ROLE_" + role))));
    }
}
