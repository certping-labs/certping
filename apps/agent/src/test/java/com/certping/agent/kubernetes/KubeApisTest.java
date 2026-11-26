// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.kubernetes;

import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.models.V1SecretList;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class KubeApisTest {

    @Test
    void listSecretsAsksTheApiServerForTlsSecretsOnly() throws Exception {
        List<HttpUrl> requests = new ArrayList<>();
        ApiClient client = new ApiClient();
        client.setBasePath("https://kube.example.test");
        client.setHttpClient(new OkHttpClient.Builder()
                .addInterceptor(chain -> {
                    requests.add(chain.request().url());
                    return new Response.Builder()
                            .request(chain.request())
                            .protocol(Protocol.HTTP_1_1)
                            .code(200)
                            .message("OK")
                            .body(ResponseBody.create("{\"apiVersion\":\"v1\",\"kind\":\"SecretList\",\"items\":[]}",
                                    MediaType.get("application/json")))
                            .build();
                })
                .build());

        V1SecretList list = new KubeApis.Core(client).listSecrets("team-a", "next-token", 500);

        assertThat(list.getItems()).isEmpty();
        assertThat(requests).hasSize(1);
        HttpUrl url = requests.get(0);
        assertThat(url.encodedPath()).isEqualTo("/api/v1/namespaces/team-a/secrets");
        assertThat(url.queryParameter("fieldSelector")).isEqualTo("type=kubernetes.io/tls");
        assertThat(url.queryParameter("continue")).isEqualTo("next-token");
        assertThat(url.queryParameter("limit")).isEqualTo("500");
    }
}
