// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.http.HttpClient;
import java.time.Duration;

import static com.certping.agent.ssl.ejbca.LocalHttpsServer.Response.of;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("EjbcaOAuthTokenProvider")
class EjbcaOAuthTokenProviderTest {

    private LocalHttpsServer idp;
    private HttpClient httpClient;

    @BeforeEach
    void setUp() throws Exception {
        idp = new LocalHttpsServer();
        // Trust the throwaway IdP cert only; the production default trust store is asserted
        // separately in EjbcaTlsContextFactoryTest.
        httpClient = EjbcaTlsContextFactory.createHttpClient(
                credentials(idp.caPem()), Duration.ofSeconds(10));
    }

    @AfterEach
    void tearDown() {
        idp.close();
    }

    @Test
    @DisplayName("fetches a token and caches it across calls")
    void cachesToken() {
        idp.respond(of(200, "{\"access_token\":\"tok-1\",\"expires_in\":3600}"));
        EjbcaOAuthTokenProvider provider = provider();

        assertThat(provider.accessToken()).isEqualTo("tok-1");
        assertThat(provider.accessToken()).isEqualTo("tok-1");

        // One IdP round trip, not one per request.
        assertThat(idp.callCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("refetches once the cached token has expired")
    void refetchesAfterExpiry() {
        // expires_in below the skew floors the lifetime at the minimum, so the first token is
        // already stale — the branch that matters is that expiry is honoured at all.
        idp.respond(of(200, "{\"access_token\":\"tok-1\",\"expires_in\":1}"),
                    of(200, "{\"access_token\":\"tok-2\",\"expires_in\":3600}"));
        EjbcaOAuthTokenProvider provider = provider();

        assertThat(provider.accessToken()).isEqualTo("tok-1");
        provider.invalidate("tok-1");

        assertThat(provider.accessToken()).isEqualTo("tok-2");
        assertThat(idp.callCount()).isEqualTo(2);
    }

    @Test
    @DisplayName("invalidate only discards the token the caller actually saw fail")
    void invalidateIsCompareAndSwap() {
        idp.respond(of(200, "{\"access_token\":\"tok-current\",\"expires_in\":3600}"));
        EjbcaOAuthTokenProvider provider = provider();
        provider.accessToken();

        // A thread holding a stale token must not discard the good one a peer just fetched.
        provider.invalidate("tok-stale-from-another-thread");

        assertThat(provider.accessToken()).isEqualTo("tok-current");
        assertThat(idp.callCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("a null argument clears unconditionally")
    void invalidateNullClearsAnyway() {
        idp.respond(of(200, "{\"access_token\":\"tok-1\",\"expires_in\":3600}"),
                    of(200, "{\"access_token\":\"tok-2\",\"expires_in\":3600}"));
        EjbcaOAuthTokenProvider provider = provider();
        provider.accessToken();

        provider.invalidate(null);

        assertThat(provider.accessToken()).isEqualTo("tok-2");
    }

    @ParameterizedTest(name = "IdP HTTP {0} is retryable, not dead-lettered")
    @ValueSource(ints = {429, 408, 500, 503})
    @DisplayName("an IdP throttle or outage must not lose a device's certificate")
    void idpThrottlingIsRetryable(int status) {
        idp.respond(of(status, "{\"error\":\"slow down\"}"));

        assertThatThrownBy(() -> provider().accessToken())
                .isInstanceOfSatisfying(RetryableAgentException.class, e ->
                        assertThat(e.getErrorCode()).isEqualTo("CA_PROVIDER_THROTTLED"));
    }

    @ParameterizedTest(name = "IdP HTTP {0} is permanent")
    @ValueSource(ints = {400, 401})
    @DisplayName("a rejected credential is permanent, because retrying cannot fix it")
    void badCredentialIsPermanent(int status) {
        idp.respond(of(status, "{\"error\":\"invalid_client\"}"));

        assertThatThrownBy(() -> provider().accessToken())
                .isInstanceOfSatisfying(PermanentAgentException.class, e ->
                        assertThat(e.getErrorCode()).isEqualTo("EJBCA_OAUTH_TOKEN_FAILED"));
    }

    @Test
    @DisplayName("a 2xx with no access_token is a failure, not an empty token")
    void missingAccessTokenIsRejected() {
        idp.respond(of(200, "{\"token_type\":\"Bearer\"}"));

        assertThatThrownBy(() -> provider().accessToken())
                .isInstanceOfSatisfying(PermanentAgentException.class, e ->
                        assertThat(e.getErrorCode()).isEqualTo("EJBCA_OAUTH_TOKEN_FAILED"));
    }

    @Test
    @DisplayName("a non-JSON token response is reported as such")
    void nonJsonTokenResponseIsRejected() {
        idp.respond(of(200, "<html>sign in</html>"));

        assertThatThrownBy(() -> provider().accessToken())
                .isInstanceOfSatisfying(PermanentAgentException.class, e ->
                        assertThat(e.getErrorCode()).isEqualTo("EJBCA_RESPONSE_INVALID"));
    }

    @Test
    @DisplayName("a malformed tokenUrl is a credential problem, not an internal error")
    void malformedTokenUrlIsACredentialProblem() {
        EjbcaOAuthTokenProvider provider = new EjbcaOAuthTokenProvider(
                new EjbcaCredentials(
                        EjbcaCredentials.AuthMethod.OAUTH_CLIENT_CREDENTIALS,
                        "https://ejbca.example.com:8443", null, null,
                        "not a url with spaces", "client-id", "secret", null, null, null),
                httpClient, JsonMapper.builderWithJackson2Defaults().build(), Duration.ofSeconds(5));

        assertThatThrownBy(provider::accessToken)
                .isInstanceOfSatisfying(PermanentAgentException.class, e ->
                        assertThat(e.getErrorCode()).isEqualTo("EJBCA_CREDENTIAL_INVALID"));
    }

    @Test
    @DisplayName("peekToken exposes the cached value for compare-and-swap invalidation")
    void peekTokenReflectsCache() {
        idp.respond(of(200, "{\"access_token\":\"tok-1\",\"expires_in\":3600}"));
        EjbcaOAuthTokenProvider provider = provider();

        assertThat(provider.peekToken()).isNull();
        provider.accessToken();
        assertThat(provider.peekToken()).isEqualTo("tok-1");
    }

    private EjbcaOAuthTokenProvider provider() {
        return new EjbcaOAuthTokenProvider(
                credentials(idp.caPem()), httpClient, JsonMapper.builderWithJackson2Defaults().build(), Duration.ofSeconds(10));
    }

    private EjbcaCredentials credentials(String caPem) {
        return new EjbcaCredentials(
                EjbcaCredentials.AuthMethod.OAUTH_CLIENT_CREDENTIALS,
                "https://ejbca.example.com:8443",
                null, null,
                idp == null ? "https://idp.example.com/token" : idp.baseUrl() + "/token",
                "client-id", "client-secret", "api://ejbca/.default", "aud", caPem);
    }
}
