// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditEventStore;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditRetentionService;
import com.certmanagement.entity.GlobalSettingsEntity;
import com.certmanagement.exception.GlobalExceptionHandler;
import com.certmanagement.repository.GlobalSettingsRepository;
import com.certmanagement.service.scheduler.SchedulerExecutionPolicy;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyIterable;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The audit retention endpoints through real method security, the real setting rules and the real error
 * mapping: super admin only, 6 to 36 months, a reason, and a clear effectiveFrom.
 */
class AuditRetentionControllerTest {

    private static final String RETENTION = "/api/v1/admin/settings/audit-retention";
    private static final Instant NOW = Instant.parse("2026-10-10T04:29:00Z");

    private AnnotationConfigApplicationContext context;
    private GlobalSettingsRepository settings;
    private AuditRecorder recorder;
    private MockMvc mvc;

    @Configuration
    @EnableMethodSecurity
    static class Wiring {
        @Bean GlobalSettingsRepository globalSettingsRepository() { return mock(GlobalSettingsRepository.class); }

        @Bean
        @DependsOnDatabaseInitialization
        AuditRecorder auditRecorder() { return mock(AuditRecorder.class); }
        @Bean AuditRetentionService auditRetentionService(GlobalSettingsRepository settings, AuditRecorder recorder) {
            AuditEventStore store = mock(AuditEventStore.class);
            when(store.oldestPartitionMonth()).thenReturn(Optional.empty());
            SchedulerExecutionPolicy policy = mock(SchedulerExecutionPolicy.class);
            when(policy.canRun("audit-retention")).thenReturn(true);
            return new AuditRetentionService(settings, recorder, store, policy, Clock.fixed(NOW, ZoneOffset.UTC),
                    "0 30 4 * * *", Duration.ofHours(24));
        }
        @Bean AuditRetentionController controller(AuditRetentionService service) {
            return new AuditRetentionController(service);
        }
    }

    @BeforeEach
    void setUp() {
        context = new AnnotationConfigApplicationContext(Wiring.class);
        settings = context.getBean(GlobalSettingsRepository.class);
        recorder = context.getBean(AuditRecorder.class);
        reset(settings);
        Map<String, GlobalSettingsEntity> table = new HashMap<>();
        table.put("audit_retention_months", GlobalSettingsEntity.builder().key("audit_retention_months").value("12")
                .updatedAt(Instant.parse("2026-01-01T00:00:00Z").atOffset(ZoneOffset.UTC)).build());
        when(settings.findById(anyString())).thenAnswer(call -> Optional.ofNullable(table.get(call.<String>getArgument(0))));
        when(settings.findByKeyForUpdate(anyString()))
                .thenAnswer(call -> Optional.ofNullable(table.get(call.<String>getArgument(0))));
        when(settings.findAllById(anyIterable())).thenAnswer(call -> {
            List<GlobalSettingsEntity> rows = new ArrayList<>();
            call.<Iterable<String>>getArgument(0).forEach(key -> Optional.ofNullable(table.get(key)).ifPresent(rows::add));
            return rows;
        });
        when(settings.save(any())).thenAnswer(call -> {
            GlobalSettingsEntity row = call.getArgument(0);
            table.put(row.getKey(), row);
            return row;
        });
        JsonMapper json = JsonMapper.builder().build();
        mvc = MockMvcBuilders.standaloneSetup(context.getBean(AuditRetentionController.class))
                .setControllerAdvice(new GlobalExceptionHandler(json))
                .setMessageConverters(new JacksonJsonHttpMessageConverter(json))
                .build();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        context.close();
    }

    @Test
    void anOrgAdminCanNeitherReadNorChangeIt() throws Exception {
        authenticate("ROLE_ORGANIZATION_ADMIN", "organization:manage", "audit:read");

        mvc.perform(get(RETENTION)).andExpect(status().isForbidden());
        mvc.perform(put(RETENTION).contentType(MediaType.APPLICATION_JSON)
                .content("{\"months\":6,\"reason\":\"contract\"}")).andExpect(status().isForbidden());

        verify(settings, never()).save(any());
        verify(recorder, never()).record(any());
    }

    @Test
    void aSuperAdminSeesThePeriodItsBoundsAndThatNothingIsScheduledUntilConfirmed() throws Exception {
        authenticate("ROLE_SUPER_ADMIN");

        mvc.perform(get(RETENTION).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.months").value(12))
                .andExpect(jsonPath("$.retentionDays").value(365))
                .andExpect(jsonPath("$.minMonths").value(6))
                .andExpect(jsonPath("$.maxMonths").value(36))
                .andExpect(jsonPath("$.confirmed").value(false))
                .andExpect(jsonPath("$.confirmedAt").doesNotExist())
                .andExpect(jsonPath("$.effectiveFrom").doesNotExist())
                .andExpect(jsonPath("$.deletionWouldStartAt").value("2026-10-11T04:30:00Z"))
                .andExpect(jsonPath("$.deletionHeldBy").doesNotExist())
                .andExpect(jsonPath("$.oldestRetainedMonth").value("2025-10"))
                .andExpect(jsonPath("$.automaticDeletionEnabled").value(true));
    }

    @Test
    void savingTheCurrentPeriodConfirmsItAndSchedulesTheFirstDropsAfterTheGrace() throws Exception {
        authenticate("ROLE_SUPER_ADMIN");

        mvc.perform(put(RETENTION).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"months\":12,\"reason\":\"Keep a year\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.confirmed").value(true))
                .andExpect(jsonPath("$.confirmedAt").value("2026-10-10T04:29:00Z"))
                .andExpect(jsonPath("$.effectiveFrom").value("2026-10-11T04:30:00Z"));
        mvc.perform(get(RETENTION)).andExpect(jsonPath("$.confirmed").value(true));

        verify(recorder, times(1)).record(any());
    }

    @ParameterizedTest
    @ValueSource(ints = {5, 37})
    void aPeriodOutOfRangeIsA400WithItsCodeAndBounds(int months) throws Exception {
        authenticate("ROLE_SUPER_ADMIN");

        mvc.perform(put(RETENTION).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"months\":" + months + ",\"reason\":\"contract\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("AUDIT_RETENTION_OUT_OF_RANGE"))
                .andExpect(jsonPath("$.minMonths").value(6))
                .andExpect(jsonPath("$.maxMonths").value(36));

        verify(settings, never()).save(any());
    }

    @ParameterizedTest
    @ValueSource(ints = {6, 36})
    void theBoundsAreAcceptedAndAShorterPeriodSaysWhenItTakesEffect(int months) throws Exception {
        authenticate("ROLE_SUPER_ADMIN");

        mvc.perform(put(RETENTION).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"months\":" + months + ",\"reason\":\"Contract ends in March\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.months").value(months))
                .andExpect(jsonPath("$.previousMonths").value(12))
                // Not the 04:30 run a minute away: the change waits out its day of grace.
                .andExpect(jsonPath("$.effectiveFrom").value("2026-10-11T04:30:00Z"));

        verify(recorder, times(2)).record(any());
    }

    @Test
    void aReasonIsRequired() throws Exception {
        authenticate("ROLE_SUPER_ADMIN");

        mvc.perform(put(RETENTION).contentType(MediaType.APPLICATION_JSON).content("{\"months\":6}"))
                .andExpect(status().isBadRequest());
        mvc.perform(put(RETENTION).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"months\":6,\"reason\":\"" + "x".repeat(501) + "\"}"))
                .andExpect(status().isBadRequest());

        verify(settings, never()).save(any());
    }

    private static void authenticate(String... authorities) {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                "caller", "n/a", Arrays.stream(authorities).map(SimpleGrantedAuthority::new).toList()));
    }
}
