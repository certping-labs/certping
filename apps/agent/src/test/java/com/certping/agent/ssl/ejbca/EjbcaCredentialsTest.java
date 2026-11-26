// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("EjbcaCredentials")
class EjbcaCredentialsTest {

    private final ObjectMapper mapper = JsonMapper.builderWithJackson2Defaults().build();

    private static final String CLIENT_CERT_JSON = """
            {
              "authMethod": "CLIENT_CERT",
              "baseUrl": "https://ejbca.internal.example.com:8443",
              "clientP12Base64": "TUlJUUFB",
              "clientP12Password": "changeit",
              "serverCaChainPem": "-----BEGIN CERTIFICATE-----\\nMIID\\n-----END CERTIFICATE-----\\n"
            }""";

    private static final String OAUTH_JSON = """
            {
              "authMethod": "OAUTH_CLIENT_CREDENTIALS",
              "baseUrl": "https://ejbca.internal.example.com:8443",
              "tokenUrl": "https://login.microsoftonline.com/tid/oauth2/v2.0/token",
              "clientId": "8f3c1e42",
              "clientSecret": "abc~secret",
              "scope": "api://ejbca/.default",
              "audience": null
            }""";

    @Nested
    @DisplayName("CLIENT_CERT")
    class ClientCert {

        @Test
        @DisplayName("parses every field")
        void parsesAllFields() {
            EjbcaCredentials creds = EjbcaCredentials.parse(CLIENT_CERT_JSON, mapper, null);

            assertThat(creds.authMethod()).isEqualTo(EjbcaCredentials.AuthMethod.CLIENT_CERT);
            assertThat(creds.baseUrl()).isEqualTo("https://ejbca.internal.example.com:8443");
            assertThat(creds.clientP12Base64()).isEqualTo("TUlJUUFB");
            assertThat(creds.clientP12Password()).isEqualTo("changeit");
            assertThat(creds.serverCaChainPem()).contains("BEGIN CERTIFICATE");
        }

        @Test
        @DisplayName("accepts an empty password for an unprotected P12")
        void emptyPasswordIsValid() {
            String json = CLIENT_CERT_JSON.replace("\"changeit\"", "\"\"");

            assertThat(EjbcaCredentials.parse(json, mapper, null).clientP12Password()).isEmpty();
        }

        @Test
        @DisplayName("rejects a missing password, which is distinct from an empty one")
        void missingPasswordIsRejected() {
            String json = CLIENT_CERT_JSON.replace("\"clientP12Password\": \"changeit\",", "");

            assertThatThrownBy(() -> EjbcaCredentials.parse(json, mapper, null))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasMessageContaining("clientP12Password");
        }

        @Test
        @DisplayName("rejects a missing P12")
        void missingP12IsRejected() {
            String json = CLIENT_CERT_JSON.replace("\"clientP12Base64\": \"TUlJUUFB\",", "");

            assertThatThrownBy(() -> EjbcaCredentials.parse(json, mapper, null))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasMessageContaining("clientP12Base64");
        }

        @Test
        @DisplayName("omitting serverCaChainPem is allowed and means the system trust store")
        void serverCaChainIsOptional() {
            String json = """
                    {"authMethod":"CLIENT_CERT","baseUrl":"https://e:8443",
                     "clientP12Base64":"x","clientP12Password":"y"}""";

            assertThat(EjbcaCredentials.parse(json, mapper, null).serverCaChainPem()).isNull();
        }
    }

    @Nested
    @DisplayName("OAUTH_CLIENT_CREDENTIALS")
    class Oauth {

        @Test
        @DisplayName("parses every field and treats a null audience as absent")
        void parsesAllFields() {
            EjbcaCredentials creds = EjbcaCredentials.parse(OAUTH_JSON, mapper, null);

            assertThat(creds.authMethod())
                    .isEqualTo(EjbcaCredentials.AuthMethod.OAUTH_CLIENT_CREDENTIALS);
            assertThat(creds.tokenUrl()).contains("microsoftonline.com");
            assertThat(creds.clientId()).isEqualTo("8f3c1e42");
            assertThat(creds.clientSecret()).isEqualTo("abc~secret");
            assertThat(creds.scope()).isEqualTo("api://ejbca/.default");
            assertThat(creds.audience()).isNull();
        }

        @Test
        @DisplayName("rejects a missing tokenUrl")
        void missingTokenUrlIsRejected() {
            String json = OAUTH_JSON.replace(
                    "\"tokenUrl\": \"https://login.microsoftonline.com/tid/oauth2/v2.0/token\",", "");

            assertThatThrownBy(() -> EjbcaCredentials.parse(json, mapper, null))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasMessageContaining("tokenUrl");
        }

        @Test
        @DisplayName("does not require a P12")
        void p12NotRequired() {
            assertThat(EjbcaCredentials.parse(OAUTH_JSON, mapper, null).clientP12Base64()).isNull();
        }
    }

    @Nested
    @DisplayName("baseUrl")
    class BaseUrl {

        @Test
        @DisplayName("the env override wins over the value in the secret")
        void overrideWins() {
            EjbcaCredentials creds = EjbcaCredentials.parse(
                    CLIENT_CERT_JSON, mapper, "https://override.example.com:8443");

            assertThat(creds.baseUrl()).isEqualTo("https://override.example.com:8443");
        }

        @Test
        @DisplayName("a trailing slash is stripped so paths never double up")
        void trailingSlashStripped() {
            EjbcaCredentials creds = EjbcaCredentials.parse(
                    CLIENT_CERT_JSON, mapper, "https://ejbca.example.com:8443/");

            assertThat(creds.baseUrl()).isEqualTo("https://ejbca.example.com:8443");
        }

        @Test
        @DisplayName("plain http is rejected because port 8080 redirects and a redirected POST loses its body")
        void httpIsRejected() {
            assertThatThrownBy(() -> EjbcaCredentials.parse(
                    CLIENT_CERT_JSON, mapper, "http://ejbca.example.com:8080"))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasMessageContaining("https");
        }
    }

    @Nested
    @DisplayName("authMethod discriminator")
    class AuthMethodDiscriminator {

        @Test
        @DisplayName("rejects an unknown method")
        void unknownMethodRejected() {
            String json = CLIENT_CERT_JSON.replace("CLIENT_CERT", "USERNAME_PASSWORD");

            assertThatThrownBy(() -> EjbcaCredentials.parse(json, mapper, null))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasMessageContaining("USERNAME_PASSWORD");
        }

        @Test
        @DisplayName("rejects a missing method")
        void missingMethodRejected() {
            String json = CLIENT_CERT_JSON.replace("\"authMethod\": \"CLIENT_CERT\",", "");

            assertThatThrownBy(() -> EjbcaCredentials.parse(json, mapper, null))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasMessageContaining("authMethod");
        }

        @Test
        @DisplayName("authMethod alone selects the shape — edition and version cannot influence it")
        void editionAndVersionCannotChangeParsing() {
            // Jackson ignores unknown fields for any input, so merely asserting "it still parses"
            // would pass vacuously. Assert instead that a *contradictory* edition/version pair
            // produces byte-identical output, which is the property we actually rely on.
            String withMisleadingHints = CLIENT_CERT_JSON.replace("\"authMethod\": \"CLIENT_CERT\",",
                    "\"authMethod\": \"CLIENT_CERT\", \"edition\": \"enterprise\", \"version\": \"7.4.3\",");

            assertThat(EjbcaCredentials.parse(withMisleadingHints, mapper, null))
                    .isEqualTo(EjbcaCredentials.parse(CLIENT_CERT_JSON, mapper, null));
        }

        @Test
        @DisplayName("keeps secrets out of toString, which is one stray log line away from disclosure")
        void toStringRedactsSecrets() {
            String rendered = EjbcaCredentials.parse(CLIENT_CERT_JSON, mapper, null).toString();

            assertThat(rendered).doesNotContain("changeit").contains("redacted");
        }
    }

    @Test
    @DisplayName("rejects an empty secret")
    void emptySecretRejected() {
        assertThatThrownBy(() -> EjbcaCredentials.parse("  ", mapper, null))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("credential-path");
    }

    @Test
    @DisplayName("rejects a secret that is not JSON")
    void nonJsonSecretRejected() {
        assertThatThrownBy(() -> EjbcaCredentials.parse("not json at all", mapper, null))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("not valid JSON");
    }
}
