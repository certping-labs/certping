// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cbom;

import com.certmanagement.config.CacheConfig;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.DiscoveredCertRepository;
import com.github.benmanes.caffeine.cache.Cache;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static com.certmanagement.config.CacheConfig.PQC_SUMMARY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The real {@link CacheConfig} wired around the real service and entity listener, repository mocked. */
class PqcSummaryCachingTest {

    private AnnotationConfigApplicationContext context;
    private CertificateRepository repository;
    private PqcReadinessService service;
    private CertificateInventoryEntityListener listener;
    private RecordingTransactionManager transactions;

    @Configuration
    @Import({CacheConfig.class, PqcReadinessService.class, CertificateInventoryEntityListener.class})
    @EnableTransactionManagement
    static class Wiring {
        @Bean RecordingTransactionManager transactionManager() { return new RecordingTransactionManager(); }
        @Bean CertificateRepository certificateRepository() { return mock(CertificateRepository.class); }
        @Bean DiscoveredCertRepository discoveredCertRepository() { return mock(DiscoveredCertRepository.class); }
    }

    static class RecordingTransactionManager extends AbstractPlatformTransactionManager {
        Runnable onCommit = () -> { };

        @Override protected Object doGetTransaction() { return new Object(); }
        @Override protected void doBegin(Object transaction, TransactionDefinition definition) { }
        @Override protected void doCommit(DefaultTransactionStatus status) { onCommit.run(); }
        @Override protected void doRollback(DefaultTransactionStatus status) { }
    }

    @BeforeEach
    void setUp() {
        context = new AnnotationConfigApplicationContext(Wiring.class);
        repository = context.getBean(CertificateRepository.class);
        service = context.getBean(PqcReadinessService.class);
        listener = context.getBean(CertificateInventoryEntityListener.class);
        transactions = context.getBean(RecordingTransactionManager.class);
        when(repository.countPqcAlgorithmsByOrganizationId(anyLong())).thenReturn(List.of());
    }

    @AfterEach
    void tearDown() {
        context.close();
    }

    @Test
    void summaryIsCachedPerOrganization() {
        service.summary(1L);
        service.summary(1L);
        service.summary(2L);

        verify(repository, times(1)).countPqcAlgorithmsByOrganizationId(1L);
        verify(repository, times(1)).countPqcAlgorithmsByOrganizationId(2L);
        assertThat(nativeCache().asMap()).containsOnlyKeys(1L, 2L);
    }

    @Test
    void certificateWriteInsideATransactionEvictsAfterTheCommit() {
        service.summary(1L);
        transactions.onCommit = () -> assertThat(nativeCache().asMap()).as("still cached at commit").hasSize(1);

        new TransactionTemplate(transactions).executeWithoutResult(status -> listener.onChange(new Object()));

        assertThat(nativeCache().asMap()).isEmpty();
        service.summary(1L);
        verify(repository, times(2)).countPqcAlgorithmsByOrganizationId(1L);
    }

    @Test
    void certificateWriteOutsideATransactionEvictsImmediately() {
        service.summary(1L);

        listener.onChange(new Object());

        assertThat(nativeCache().asMap()).isEmpty();
    }

    @Test
    void entriesExpireAndTheCacheIsBounded() {
        Cache<Object, Object> cache = nativeCache();

        assertThat(cache.policy().expireAfterWrite().orElseThrow().getExpiresAfter(TimeUnit.SECONDS))
                .isEqualTo(Duration.ofMinutes(5).toSeconds());
        assertThat(cache.policy().eviction().orElseThrow().getMaximum()).isEqualTo(1_000);
    }

    @SuppressWarnings("unchecked")
    private Cache<Object, Object> nativeCache() {
        CaffeineCache cache = (CaffeineCache) context.getBean(CacheManager.class).getCache(PQC_SUMMARY);
        return cache.getNativeCache();
    }
}
