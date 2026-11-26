// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

import java.time.Duration;

/**
 * In-process caches. Caching advice is ordered outside transaction advice so an eviction runs
 * after the commit that made it necessary.
 */
@Configuration
@EnableCaching(order = Ordered.LOWEST_PRECEDENCE - 1)
public class CacheConfig {

    public static final String FEATURE_FLAGS = "feature-flags";
    public static final String PQC_SUMMARY = "pqc-summary";

    /** How long a pod may keep a flag decision when it cannot hear of a change (SharedFeatureFlags). */
    static final Duration FEATURE_FLAGS_TTL = Duration.ofSeconds(60);
    static final long FEATURE_FLAGS_MAX_ENTRIES = 250_000;

    /** One small summary per organization; bounds cross-pod staleness after a certificate write. */
    static final Duration PQC_SUMMARY_TTL = Duration.ofMinutes(5);
    static final long PQC_SUMMARY_MAX_ENTRIES = 1_000;

    @Bean
    public CacheManager cacheManager() {
        CaffeineCacheManager manager = new CaffeineCacheManager();
        manager.registerCustomCache(FEATURE_FLAGS, Caffeine.newBuilder()
                .expireAfterWrite(FEATURE_FLAGS_TTL)
                .maximumSize(FEATURE_FLAGS_MAX_ENTRIES)
                .recordStats()
                .build());
        manager.registerCustomCache(PQC_SUMMARY, Caffeine.newBuilder()
                .expireAfterWrite(PQC_SUMMARY_TTL)
                .maximumSize(PQC_SUMMARY_MAX_ENTRIES)
                .recordStats()
                .build());
        return manager;
    }
}
