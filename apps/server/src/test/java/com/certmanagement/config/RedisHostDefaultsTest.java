// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.StandardEnvironment;

/**
 * Revoked access tokens live in Redis, so an installed server must reach the installation's Redis and
 * never fall back to localhost, where it would find none and let logged-out tokens through. The
 * selfhosted profile (the images' default) points at the kits' redis service unless REDIS_HOST says
 * otherwise; only a run without a profile, on a developer's machine, uses localhost.
 */
class RedisHostDefaultsTest {

    @Test
    void selfhostedDefaultsToTheKitsRedisService() throws IOException {
        assertThat(redisHost("selfhosted", Map.of())).isEqualTo("redis");
    }

    @Test
    void selfhostedUsesTheConfiguredRedisHost() throws IOException {
        assertThat(redisHost("selfhosted", Map.of("REDIS_HOST", "redis.internal"))).isEqualTo("redis.internal");
    }

    @Test
    void localRunsDefaultToLocalhost() throws IOException {
        assertThat(redisHost(null, Map.of())).isEqualTo("localhost");
    }

    private static String redisHost(String profile, Map<String, Object> variables) throws IOException {
        StandardEnvironment environment = ProfileEnvironment.of(profile, variables);
        return Binder.get(environment).bind("spring.data.redis.host", String.class).get();
    }
}
