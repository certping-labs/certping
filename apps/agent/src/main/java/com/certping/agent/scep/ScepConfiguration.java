// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.platform.DeviceSourceCredentialRegistry;
import com.certping.agent.platform.DeviceSourceProfileRegistry;
import com.certping.agent.scep.ca.EjbcaScepCaBackend;
import com.certping.agent.scep.ca.ScepCaBackend;
import com.certping.agent.scep.ca.SmallstepScepCaBackend;
import com.certping.agent.scep.intune.IntuneScepClient;
import com.certping.agent.scep.intune.IntuneScepValidator;
import com.certping.agent.scep.intune.MicrosoftIntuneScepValidator;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.ssl.ejbca.EjbcaSigningService;
import com.certping.agent.ssl.ejbca.EjbcaRevocationService;
import com.certping.agent.ssl.smallstep.SmallstepSigningService;
import com.certping.agent.ssl.smallstep.SmallstepRevocationService;
import tools.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import java.security.Security;
import java.time.Clock;

/**
 * Wires the SCEP layer, only when {@code agent.scep.enabled=true}. Registers the BouncyCastle JCA
 * provider (the codec needs it) and selects the CA backend and Intune validator by property. The
 * controller and exception advice are component-scanned under the same flag.
 */
@Configuration
@ConditionalOnProperty(prefix = "agent.scep", name = "enabled", havingValue = "true")
public class ScepConfiguration {

    public ScepConfiguration() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Bean
    @ConditionalOnProperty(prefix = "agent.scep.ca", name = "backend", havingValue = "ejbca", matchIfMissing = true)
    ScepCaBackend ejbcaScepCaBackend(EjbcaSigningService ejbca,
                                     EjbcaRevocationService revocationService,
                                     SecretStore secretStore,
                                     AgentProperties properties, ObjectMapper objectMapper) {
        if (!properties.getEjbca().isEnabled()) {
            throw new IllegalStateException(
                    "agent.scep.ca.backend=ejbca requires agent.ejbca.enabled=true");
        }
        return new EjbcaScepCaBackend(
                ejbca, revocationService, secretStore, properties, objectMapper);
    }

    @Bean
    @ConditionalOnProperty(prefix = "agent.scep.ca", name = "backend", havingValue = "smallstep")
    ScepCaBackend smallstepScepCaBackend(SmallstepSigningService smallstep,
                                         SmallstepRevocationService revocationService,
                                         SecretStore secretStore,
                                         AgentProperties properties, ObjectMapper objectMapper) {
        if (!properties.getSmallstep().isEnabled()) {
            throw new IllegalStateException(
                    "agent.scep.ca.backend=smallstep requires agent.smallstep.enabled=true");
        }
        return new SmallstepScepCaBackend(
                smallstep, revocationService, secretStore, properties, objectMapper);
    }

    @Bean
    IntuneScepValidator intuneScepValidator(AgentProperties properties, IntuneScepClient client,
                                            DeviceSourceCredentialRegistry credentialRegistry,
                                            ObjectMapper objectMapper) {
        AgentProperties.IntuneScepProperties intune = properties.getScep().getIntune();
        if (!intune.isEnabled()) {
            throw new IllegalStateException(
                    "agent.scep.enabled=true requires agent.scep.intune.enabled=true; "
                            + "SCEP enrollment must not run without Intune challenge validation");
        }
        // Tenant credentials are per source route, resolved from the device-source credential
        // registry at validation time — one agent can serve several Intune connections.
        return new MicrosoftIntuneScepValidator(client, credentialRegistry, objectMapper,
                intune.getProviderNameAndVersion());
    }

    @Bean
    PkiMessageCodec pkiMessageCodec() {
        return new PkiMessageCodec();
    }

    /** Bounds the unauthenticated SCEP body before Spring buffers it into a byte[]. */
    @Bean
    FilterRegistrationBean<ScepRequestSizeFilter> scepRequestSizeFilter() {
        FilterRegistrationBean<ScepRequestSizeFilter> registration =
                new FilterRegistrationBean<>(new ScepRequestSizeFilter());
        registration.addUrlPatterns("/scep/*");
        return registration;
    }

    @Bean
    ScepTransactionStore scepTransactionStore(AgentProperties properties) {
        return new ScepTransactionStore(properties);
    }

    @Bean
    ScepEndpointRegistry scepEndpointRegistry(AgentProperties properties, ScepCaBackend caBackend,
                                              DeviceSourceProfileRegistry sourceRegistry) {
        return new ScepEndpointRegistry(properties, caBackend, sourceRegistry);
    }

    @Bean
    ScepService scepService(ScepEndpointRegistry registry, PkiMessageCodec codec,
                            IntuneScepValidator intune, ScepTransactionStore transactions,
                            AgentMessageSender messageSender, Clock clock,
                            ScepProfileHintResolver profileHints) {
        return new ScepService(registry, codec, intune, transactions, messageSender, clock,
                profileHints);
    }
}
