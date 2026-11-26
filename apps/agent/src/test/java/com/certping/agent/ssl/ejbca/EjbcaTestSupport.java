// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/**
 * Builds a fully wired {@link EjbcaSigningService} for tests outside this package.
 *
 * <p>Exists so {@link EjbcaClient} can stay package-private in production code. Widening its
 * visibility just to let an integration test construct it would trade a real encapsulation
 * boundary for test convenience.
 */
public final class EjbcaTestSupport {

    private EjbcaTestSupport() {
    }

    public static EjbcaSigningService signingService(AgentProperties properties,
                                                     SecretStore secretStore) {
        EjbcaClient client = new EjbcaClient(properties, secretStore, JsonMapper.builderWithJackson2Defaults().build());
        return new EjbcaSigningService(client, new EndEntityNameResolver(), properties);
    }
}
