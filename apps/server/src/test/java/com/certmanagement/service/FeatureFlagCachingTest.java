// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.config.CacheConfig;
import com.certmanagement.entity.GlobalFeatureFlag;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.GlobalFeatureFlagRepository;
import com.certmanagement.repository.OrgTypeFeatureFlagRepository;
import com.certmanagement.repository.OrganizationFeatureFlagRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.service.lifecycle.FeatureLifecycleService;
import com.certmanagement.service.lifecycle.ForcedFlagChanges;
import com.certmanagement.testing.BeanProviders;
import com.github.benmanes.caffeine.cache.Cache;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static com.certmanagement.config.CacheConfig.FEATURE_FLAGS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The real {@link CacheConfig} wired around the real resolver and service, repositories mocked. */
class FeatureFlagCachingTest {

    private static final String KEY = "SOME_FLAG";

    private AnnotationConfigApplicationContext context;
    private GlobalFeatureFlagRepository globalRepo;
    private FeatureFlagService service;
    private RecordingTransactionManager transactions;

    @Configuration
    @Import(CacheConfig.class)
    @EnableTransactionManagement
    static class Wiring {

        @Bean RecordingTransactionManager transactionManager() { return new RecordingTransactionManager(); }
        @Bean ChangeRecorder changes() { return new ChangeRecorder(); }
        @Bean GlobalFeatureFlagRepository globalRepo() { return mock(GlobalFeatureFlagRepository.class); }
        @Bean OrganizationFeatureFlagRepository orgRepo() { return mock(OrganizationFeatureFlagRepository.class); }
        @Bean OrgTypeFeatureFlagRepository orgTypeRepo() { return mock(OrgTypeFeatureFlagRepository.class); }
        @Bean OrganizationRepository organizationRepo() { return mock(OrganizationRepository.class); }
        @Bean FeatureFlagResolver resolver(GlobalFeatureFlagRepository g, OrganizationFeatureFlagRepository o,
                                           OrgTypeFeatureFlagRepository t, OrganizationRepository r) {
            return new FeatureFlagResolver(g, o, t, r);
        }
        @Bean FeatureFlagService service(GlobalFeatureFlagRepository g, OrganizationFeatureFlagRepository o,
                                         OrgTypeFeatureFlagRepository t, OrganizationRepository r,
                                         FeatureFlagResolver resolver,
                                         ApplicationEventPublisher events) {
            return new FeatureFlagService(g, o, t, r, resolver, events,
                    mock(com.certmanagement.service.audit.FeatureFlagChangeAudit.class),
                    BeanProviders.of(FeatureLifecycleService.class, mock(FeatureLifecycleService.class)),
                    BeanProviders.of(ForcedFlagChanges.class, mock(ForcedFlagChanges.class)));
        }
    }

    static class ChangeRecorder {
        int announced;

        @TransactionalEventListener(fallbackExecution = true)
        void on(FeatureFlagsChangedEvent event) { announced++; }
    }

    static class RecordingTransactionManager extends AbstractPlatformTransactionManager {
        int commits;
        Runnable onCommit = () -> { };

        @Override protected Object doGetTransaction() { return new Object(); }
        @Override protected void doBegin(Object transaction, TransactionDefinition definition) { }
        @Override protected void doCommit(DefaultTransactionStatus status) { onCommit.run(); commits++; }
        @Override protected void doRollback(DefaultTransactionStatus status) { }
    }

    @BeforeEach
    void setUp() {
        context = new AnnotationConfigApplicationContext(Wiring.class);
        globalRepo = context.getBean(GlobalFeatureFlagRepository.class);
        service = context.getBean(FeatureFlagService.class);
        transactions = context.getBean(RecordingTransactionManager.class);
        GlobalFeatureFlag flag = GlobalFeatureFlag.builder()
                .featureKey(KEY).scope("PLATFORM").category("PLATFORM").enabled(true).build();
        when(globalRepo.findResolutionViewByFeatureKey(anyString())).thenReturn(Optional.of(view(flag)));
        when(globalRepo.findByFeatureKey(anyString())).thenReturn(Optional.of(flag));
        when(globalRepo.save(flag)).thenReturn(flag);
    }

    @AfterEach
    void tearDown() {
        context.close();
    }

    @Test
    void secondCheckIsServedFromTheCache() {
        service.isEnabled(KEY, 1L);
        service.assertEnabled(KEY, 1L);

        verify(globalRepo, times(1)).findResolutionViewByFeatureKey(KEY);
    }

    @Test
    void entriesAreKeyedByFlagAndOrganization() {
        service.isEnabled(KEY, 1L);
        service.isEnabled(KEY, 2L);
        service.isEnabled(KEY, null);
        service.isEnabled("OTHER", 1L);

        verify(globalRepo, times(3)).findResolutionViewByFeatureKey(KEY);
        verify(globalRepo, times(1)).findResolutionViewByFeatureKey("OTHER");
        assertThat(nativeCache().asMap()).containsOnlyKeys(
                KEY + ":1", KEY + ":2", KEY + ":platform", "OTHER:1");
    }

    @Test
    void writesEvictEverythingAfterTheCommit() {
        service.isEnabled(KEY, 1L);
        service.isEnabled(KEY, 2L);
        transactions.onCommit = () -> assertThat(nativeCache().asMap()).as("still cached at commit").hasSize(2);

        service.updateGlobal(KEY, false, "test");

        assertThat(transactions.commits).isEqualTo(1);
        assertThat(nativeCache().asMap()).isEmpty();
        service.isEnabled(KEY, 1L);
        verify(globalRepo, times(3)).findResolutionViewByFeatureKey(KEY);
    }

    @Test
    void aWriteIsAnnouncedToTheOtherPods_onlyOnceItCommits() {
        ChangeRecorder changes = context.getBean(ChangeRecorder.class);
        transactions.onCommit = () -> assertThat(changes.announced).as("announced before the commit").isZero();

        service.updateGlobal(KEY, false, "test");

        assertThat(changes.announced).isEqualTo(1);
    }

    @Test
    void aWriteThatFails_isNotAnnounced() {
        when(globalRepo.findByFeatureKey("MISSING")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.updateGlobal("MISSING", false, "test"))
                .isInstanceOf(ResourceNotFoundException.class);

        assertThat(context.getBean(ChangeRecorder.class).announced).isZero();
    }

    @Test
    void theOrganizationsEffectiveMapIsCachedAndTheDisabledKeysComeFromIt() {
        OrganizationFeatureFlagRepository orgRepo = stubCatalog();

        assertThat(service.effectiveMap(7L)).containsOnly(entry(KEY, true), entry("OFF_FLAG", false));
        assertThat(service.effectiveMap(7L)).containsOnly(entry(KEY, true), entry("OFF_FLAG", false));
        assertThat(service.disabledFeatureKeys(7L)).containsExactly("OFF_FLAG");

        verify(globalRepo, times(1)).findAll();
        verify(orgRepo, times(1)).findAllByOrganizationId(7L);
        assertThat(nativeCache().asMap()).containsOnlyKeys("effective:7");
    }

    @Test
    void aFlagWriteOrAnotherPodsChangeDropsTheEffectiveMap() {
        stubCatalog();
        service.effectiveMap(7L);

        service.updateGlobal(KEY, false, "test");
        service.effectiveMap(7L);
        // What SharedFeatureFlags.pollForChanges does when another pod announces a change.
        context.getBean(CacheManager.class).getCache(FEATURE_FLAGS).clear();
        service.disabledFeatureKeys(7L);

        verify(globalRepo, times(3)).findAll();
    }

    @Test
    void entriesExpireAndTheCacheIsBounded() {
        Cache<Object, Object> cache = nativeCache();

        assertThat(cache.policy().expireAfterWrite().orElseThrow().getExpiresAfter(TimeUnit.SECONDS))
                .isEqualTo(Duration.ofSeconds(60).toSeconds());
        assertThat(cache.policy().eviction().orElseThrow().getMaximum()).isEqualTo(250_000);
        assertThat(cache.policy().isRecordingStats()).isTrue();
    }

    /** KEY on, OFF_FLAG off, organization 7 without overrides or a type. */
    private OrganizationFeatureFlagRepository stubCatalog() {
        GlobalFeatureFlag on = globalRepo.findByFeatureKey(KEY).orElseThrow();
        GlobalFeatureFlag off = GlobalFeatureFlag.builder()
                .featureKey("OFF_FLAG").scope("PLATFORM").category("PLATFORM").enabled(false).build();
        when(globalRepo.findAll()).thenReturn(List.of(on, off));
        when(context.getBean(OrganizationRepository.class).findOrgTypeById(7L)).thenReturn(Optional.empty());
        OrganizationFeatureFlagRepository orgRepo = context.getBean(OrganizationFeatureFlagRepository.class);
        when(orgRepo.findAllByOrganizationId(7L)).thenReturn(List.of());
        return orgRepo;
    }

    @SuppressWarnings("unchecked")
    private Cache<Object, Object> nativeCache() {
        CaffeineCache cache = (CaffeineCache) context.getBean(CacheManager.class).getCache(FEATURE_FLAGS);
        return cache.getNativeCache();
    }

    private static GlobalFeatureFlagRepository.ResolutionView view(GlobalFeatureFlag g) {
        return new GlobalFeatureFlagRepository.ResolutionView() {
            @Override public Boolean getEnabled() { return g.getEnabled(); }
            @Override public String getCategory() { return g.getCategory(); }
            @Override public String getScope() { return g.getScope(); }
        };
    }
}
