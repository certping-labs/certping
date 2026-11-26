// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.secrets;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Slf4j
@Configuration
public class SecretStoreConfig {

    @Bean
    public SecretStore secretStore(SecretStoreProperties properties,
                                   List<SecretStoreDriver> drivers) {
        SecretStoreProvider active = properties.getProvider();
        if (active == null) {
            throw new IllegalStateException("agent.secret-store.provider is required");
        }
        SecretStoreDriver picked = drivers.stream()
                .filter(d -> d.provider() == active)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "No SecretStoreDriver registered for provider " + active
                                + " — available: " + drivers.stream().map(d -> d.provider().name()).toList()));
        log.info("SecretStore active: provider={}, driver={}",
                active, picked.getClass().getSimpleName());
        return picked;
    }
}
