// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.scheduling.annotation.Scheduled;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Fails when a background job is added without declaring its tier and flags in {@link JobPolicy}.
 * Reads the production class files (no Spring context, so it runs in about a second) for every
 * method Spring schedules ({@code @Scheduled}, repeated through {@code @Schedules}, or as a
 * meta-annotation), every concrete {@link DrainableCron}, and every class that schedules work through
 * a scheduler API instead, which must be on {@link #PROGRAMMATIC_SCHEDULER_ALLOWLIST}.
 */
class JobPolicyRegistrationTest {

    /**
     * The only production classes allowed to use a scheduler API directly, each with why it is not an
     * unregistered background job. Adding one here needs the same review as a new job.
     */
    static final Map<String, String> PROGRAMMATIC_SCHEDULER_ALLOWLIST = Map.of(
            SchedulerStartupJoiner.class.getName(),
            "Moves the one-off startup join off the boot thread; every drain it joins runs through"
                    + " DrainRunner under its registered job name, after SchedulerExecutionPolicy.canRun.",
            SchedulerConfig.class.getName(),
            "Builds the TaskScheduler bean the @Scheduled methods checked here run on; schedules nothing itself.",
            "com.certmanagement.service.status.PublicStatusRefresher",
            "Reads this pod's own dependencies for the public status document every 30 s on its own thread;"
                    + " it changes no data and must keep running while jobs are paused or killed.",
            "com.certmanagement.messaging.QueueAgentResponseWorker",
            "The PostgreSQL message transport: renews locks on in-flight agent results and does the queue's"
                    + " own housekeeping (lock expiry, TTL). It is the broker, so it must run while jobs are paused.");

    private static List<Class<?>> scheduledOwners;
    private static List<Class<?>> drainableCrons;

    @BeforeAll
    static void scanProductionClasses() {
        scheduledOwners = ProductionJobScan.scheduledOwners();
        drainableCrons = ProductionJobScan.drainableCrons();
    }

    @Test
    void theScanFindsTheKnownJobs() {
        assertThat(scheduledOwners).contains(SchedulerJobs.class, SchedulerSupervisor.class, QueueDepthAlertService.class);
        assertThat(drainableCrons).contains(RenewalTriggerService.class, CertExpiryCleanupService.class);
    }

    @Test
    void everyScheduledMethodNamesARegisteredJob() {
        assertThat(unregisteredScheduledMethods(scheduledOwners))
                .as("@Scheduled methods need @RegisteredJob naming a JobPolicy entry")
                .isEmpty();
    }

    @Test
    void repeatedAndMetaAnnotatedSchedulesAreDetected() {
        assertThat(List.of(RepeatedSchedules.class, MetaScheduled.class))
                .allSatisfy(fixture -> assertThat(ProductionJobScan.declaresScheduledMethods(
                        ProductionJobScan.read(fixture))).as("%s found by the class-file scan", fixture).isTrue());
        assertThat(unregisteredScheduledMethods(List.of(RepeatedSchedules.class, MetaScheduled.class)))
                .containsExactlyInAnyOrder("RepeatedSchedules#twiceADay", "MetaScheduled#everyMinute");
        assertThat(unregisteredScheduledMethods(List.of(RegisteredMetaScheduled.class))).isEmpty();
    }

    @Test
    void onlyAllowlistedClassesScheduleWorkProgrammatically() {
        assertThat(ProductionJobScan.programmaticSchedulerUsers())
                .as("scheduler APIs used outside @Scheduled; register the job or justify it in the allowlist")
                .isSubsetOf(PROGRAMMATIC_SCHEDULER_ALLOWLIST.keySet())
                .contains(SchedulerStartupJoiner.class.getName());
    }

    private static List<String> unregisteredScheduledMethods(List<Class<?>> owners) {
        List<String> unregistered = new ArrayList<>();
        for (Method method : ProductionJobScan.scheduledMethods(owners)) {
            RegisteredJob registration = method.getAnnotation(RegisteredJob.class);
            if (registration == null || JobPolicy.byName(registration.value()).isEmpty()) {
                unregistered.add(method.getDeclaringClass().getSimpleName() + "#" + method.getName());
            }
        }
        return unregistered;
    }

    @Test
    void everyDrainableCronNamesARegisteredJob() {
        List<String> unregistered = drainableCrons.stream()
                .filter(type -> {
                    CronJobFor jobFor = type.getAnnotation(CronJobFor.class);
                    return jobFor == null || JobPolicy.byName(jobFor.value()).isEmpty();
                })
                .map(Class::getSimpleName)
                .toList();
        assertThat(unregistered)
                .as("DrainableCron beans need @CronJobFor naming a JobPolicy entry")
                .isEmpty();
    }

    @Test
    void everyRegistryEntryIsUsedByAJob() {
        Set<String> used = new HashSet<>();
        ProductionJobScan.scheduledMethods(scheduledOwners).stream()
                .map(m -> m.getAnnotation(RegisteredJob.class))
                .filter(java.util.Objects::nonNull)
                .forEach(r -> used.add(r.value()));
        drainableCrons.forEach(type -> used.add(type.getAnnotation(CronJobFor.class).value()));

        Set<String> stale = Arrays.stream(JobPolicy.values())
                .map(JobPolicy::jobName)
                .filter(name -> !used.contains(name))
                .collect(Collectors.toSet());
        assertThat(stale).as("JobPolicy entries no job runs under").isEmpty();
    }

    @Test
    void onlyFeatureWorkDeclaresFeatureFlags() {
        for (JobPolicy policy : JobPolicy.values()) {
            if (policy.tier() == JobTier.FEATURE_WORK) {
                assertThat(policy.featureFlags()).as("%s is FEATURE_WORK", policy).isNotEmpty();
            } else {
                assertThat(policy.featureFlags()).as("%s is %s", policy, policy.tier()).isEmpty();
            }
        }
    }

    /** A cron job repeated through the {@code @Schedules} container. */
    static class RepeatedSchedules {
        @Scheduled(cron = "0 0 6 * * *")
        @Scheduled(cron = "0 0 18 * * *")
        void twiceADay() {
        }
    }

    /** A team shortcut annotation carrying {@code @Scheduled}. */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @Scheduled(fixedDelay = 60_000)
    @interface EveryMinute {
    }

    static class MetaScheduled {
        @EveryMinute
        void everyMinute() {
        }
    }

    static class RegisteredMetaScheduled {
        @RegisteredJob("scheduler-supervisor")
        @EveryMinute
        void everyMinute() {
        }
    }
}
