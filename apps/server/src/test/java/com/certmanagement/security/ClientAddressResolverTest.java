// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.env.SystemEnvironmentPropertySource;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientAddressResolverTest {

    private static final String FDID = "0fd00000-0000-4000-8000-0000000000fd";

    private static MockHttpServletRequest from(String peer, String... forwardedFor) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr(peer);
        for (String value : forwardedFor) {
            request.addHeader("X-Forwarded-For", value);
        }
        return request;
    }

    private static MockHttpServletRequest viaFrontDoor(String fdid, String clientIp) {
        MockHttpServletRequest request = from("10.20.0.122", "10.20.0.63");
        if (fdid != null) {
            request.addHeader("X-Azure-FDID", fdid);
        }
        if (clientIp != null) {
            request.addHeader("X-Azure-ClientIP", clientIp);
        }
        return request;
    }

    @Nested
    class LastProxyHop {

        private final ClientAddressResolver resolver = new ClientAddressResolver(ClientIpSource.LAST_PROXY_HOP, null);

        @Test
        void takesTheRightmostForwardedEntryFromAPrivatePeerAndIgnoresTheSpoofedLeftmostOne() {
            assertThat(resolver.resolve(from("10.0.0.5", "198.51.100.66, 203.0.113.9"))).isEqualTo("203.0.113.9");
        }

        @Test
        void takesTheLastEntryOfTheLastHeaderWhenTheHeaderIsRepeated() {
            assertThat(resolver.resolve(from("10.0.0.5", "198.51.100.66", "192.0.2.1, 203.0.113.9")))
                    .isEqualTo("203.0.113.9");
        }

        @ParameterizedTest
        @ValueSource(strings = {"127.0.0.1", "::1", "192.168.1.2", "172.16.0.9", "100.64.0.1", "fd00::5"})
        void believesTheHeaderFromLoopbackAndPrivatePeers(String peer) {
            assertThat(resolver.resolve(from(peer, "203.0.113.9"))).isEqualTo("203.0.113.9");
        }

        @Test
        void aPublicPeerIsTheClientWhateverTheHeaderSays() {
            assertThat(resolver.resolve(from("198.51.100.7", "203.0.113.9"))).isEqualTo("198.51.100.7");
        }

        @Test
        void withoutTheHeaderThePeerIsTheClient() {
            assertThat(resolver.resolve(from("10.0.0.5"))).isEqualTo("10.0.0.5");
        }

        @ParameterizedTest
        @ValueSource(strings = {"203.0.113.9, unknown", "203.0.113.9,", "203.0.113.9, _hidden", "  "})
        void anUnreadableRightmostEntryFallsBackToThePeer(String header) {
            assertThat(resolver.resolve(from("10.0.0.5", header))).isEqualTo("10.0.0.5");
        }

        @Test
        void neverReadsFrontDoorHeaders() {
            assertThat(resolver.resolve(viaFrontDoor(FDID, "203.0.113.9"))).isEqualTo("10.20.0.63");
        }
    }

    @Nested
    class FrontDoor {

        private final ClientAddressResolver resolver = new ClientAddressResolver(ClientIpSource.FRONT_DOOR, FDID);

        @Test
        void believesTheFrontDoorClientWhenTheProfileIdMatches() {
            assertThat(resolver.resolve(viaFrontDoor(FDID, "203.0.113.9"))).isEqualTo("203.0.113.9");
        }

        @Test
        void toleratesSurroundingWhitespaceInTheProfileId() {
            assertThat(resolver.resolve(viaFrontDoor(" " + FDID + " ", "203.0.113.9"))).isEqualTo("203.0.113.9");
        }

        @Test
        void anotherProfileIdFallsBackToTheLastProxyHop() {
            assertThat(resolver.resolve(viaFrontDoor("00000000-0000-0000-0000-000000000000", "203.0.113.9")))
                    .isEqualTo("10.20.0.63");
        }

        @Test
        void noProfileIdFallsBackToTheLastProxyHop() {
            assertThat(resolver.resolve(viaFrontDoor(null, "203.0.113.9"))).isEqualTo("10.20.0.63");
        }

        @Test
        void anUnreadableFrontDoorClientFallsBackToTheLastProxyHop() {
            assertThat(resolver.resolve(viaFrontDoor(FDID, "not-an-ip"))).isEqualTo("10.20.0.63");
            assertThat(resolver.resolve(viaFrontDoor(FDID, null))).isEqualTo("10.20.0.63");
        }

        @Test
        void normalisesAnIpv6FrontDoorClient() {
            assertThat(resolver.resolve(viaFrontDoor(FDID, "2001:DB8:0:0:0:0:0:1"))).isEqualTo("2001:db8::1");
        }

        @Test
        void withoutAConfiguredIdNothingIsBelieved() {
            ClientAddressResolver unconfigured = new ClientAddressResolver(ClientIpSource.FRONT_DOOR, " ");

            assertThat(unconfigured.resolve(viaFrontDoor(FDID, "203.0.113.9"))).isEqualTo("10.20.0.63");
            assertThat(unconfigured.resolve(viaFrontDoor("", "203.0.113.9"))).isEqualTo("10.20.0.63");
        }
    }

    @Nested
    class Peer {

        private final ClientAddressResolver resolver = new ClientAddressResolver(ClientIpSource.PEER, FDID);

        @Test
        void isTheRemoteAddressWhateverTheHeadersSay() {
            MockHttpServletRequest request = viaFrontDoor(FDID, "203.0.113.9");

            assertThat(resolver.resolve(request)).isEqualTo("10.20.0.122");
        }
    }

    /**
     * In Kubernetes, Tomcat's RemoteIpValve runs first. It has already replaced getRemoteAddr() with an
     * X-Forwarded-For entry and removed the header, so the resolver sees a rewritten address and no
     * X-Forwarded-For at all.
     */
    @Nested
    class BehindTheRemoteIpValve {

        private static final String FRONT_DOOR_CLIENT = "198.51.100.20";

        private MockHttpServletRequest rewrittenTo(String remoteAddr, boolean withFrontDoorHeaders) {
            MockHttpServletRequest request = from(remoteAddr);
            if (withFrontDoorHeaders) {
                request.addHeader("X-Azure-FDID", FDID);
                request.addHeader("X-Azure-ClientIP", FRONT_DOOR_CLIENT);
            }
            return request;
        }

        /**
         * 10.20.0.122 is the usual case behind an ingress: its peer was a cluster node (source-NAT), and the
         * valve made the node the remote address. 203.0.113.9 is the case where X-Forwarded-For carried a public entry
         * and the valve took it.
         */
        @ParameterizedTest
        @CsvSource({
                "PEER,           10.20.0.122, false, 10.20.0.122",
                "PEER,           10.20.0.122, true,  10.20.0.122",
                "PEER,           203.0.113.9,  false, 203.0.113.9",
                "LAST_PROXY_HOP, 10.20.0.122, false, 10.20.0.122",
                "LAST_PROXY_HOP, 10.20.0.122, true,  10.20.0.122",
                "LAST_PROXY_HOP, 203.0.113.9,  false, 203.0.113.9",
                "FRONT_DOOR,     10.20.0.122, true,  198.51.100.20",
                "FRONT_DOOR,     10.20.0.122, false, 10.20.0.122",
                "FRONT_DOOR,     203.0.113.9,  false, 203.0.113.9",
        })
        void eachModeAnswersFromTheRewrittenAddress(ClientIpSource source, String remoteAddr,
                                                    boolean withFrontDoorHeaders, String expected) {
            ClientAddressResolver resolver = new ClientAddressResolver(source, FDID);

            assertThat(resolver.resolve(rewrittenTo(remoteAddr, withFrontDoorHeaders))).isEqualTo(expected);
        }
    }

    @Nested
    class Normalisation {

        private final ClientAddressResolver resolver = new ClientAddressResolver(ClientIpSource.PEER, null);

        @ParameterizedTest
        @CsvSource({
                "203.0.113.9,              203.0.113.9",
                "' 203.0.113.9 ',          203.0.113.9",
                "203.0.113.9:8080,         203.0.113.9",
                "2001:DB8:0:0:0:0:0:1,     2001:db8::1",
                "[2001:db8::1],            2001:db8::1",
                "[2001:db8::1]:443,        2001:db8::1",
                "fe80::1%eth0,             fe80::1",
                "[fe80::1%25eth0]:8443,    fe80::1",
                "::ffff:203.0.113.9,       203.0.113.9",
                "0:0:0:0:0:0:0:1,          ::1",
        })
        void readsAddressesInTheirCommonSpellings(String raw, String expected) {
            assertThat(resolver.resolve(from(raw))).isEqualTo(expected);
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "unknown", "1.2.3", "1.2.3.4.5", "256.1.1.1", "203.0.113.9:http",
                "203.0.113.9:123456", "[2001:db8::1", "2001:db8::1]:80", "[2001:db8::1]x", ":::", "example.com",
                "localhost", "_hidden", "1.2.3.4, 5.6.7.8"})
        void refusesAnythingElse(String raw) {
            assertThat(resolver.resolve(from(raw))).isNull();
        }

        @Test
        void capsTheLength() {
            assertThat(resolver.resolve(from("fe80::1%" + "a".repeat(56)))).isEqualTo("fe80::1");
            assertThat(resolver.resolve(from("fe80::1%" + "a".repeat(57)))).isNull();
        }

        @Test
        void aMissingRequestHasNoClient() {
            assertThat(resolver.resolve(null)).isNull();
        }
    }

    @Nested
    class Configuration {

        @Test
        void parsesTheSourceLeniently() {
            assertThat(ClientIpSource.parse("front-door")).isEqualTo(ClientIpSource.FRONT_DOOR);
            assertThat(ClientIpSource.parse(" peer ")).isEqualTo(ClientIpSource.PEER);
            assertThat(ClientIpSource.parse("Last_Proxy_Hop")).isEqualTo(ClientIpSource.LAST_PROXY_HOP);
            assertThat(ClientIpSource.parse(null)).isEqualTo(ClientIpSource.LAST_PROXY_HOP);
            assertThat(ClientIpSource.parse("")).isEqualTo(ClientIpSource.LAST_PROXY_HOP);
        }

        @Test
        void anUnknownSourceFailsTheStart() {
            assertThatThrownBy(() -> ClientIpSource.parse("X_FORWARDED_FOR"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("certping.client-ip.source");
        }

        @Test
        void defaultsToTheLastProxyHop() {
            new ApplicationContextRunner()
                    .withUserConfiguration(ClientAddressResolver.class)
                    .run(context -> assertThat(context.getBean(ClientAddressResolver.class).source())
                            .isEqualTo(ClientIpSource.LAST_PROXY_HOP));
        }

        /** The environment variables a deployment behind Azure Front Door sets. */
        @Test
        void bindsTheEnvironmentVariablesADeploymentSets() {
            new ApplicationContextRunner()
                    .withInitializer(context -> context.getEnvironment().getPropertySources().addFirst(
                            new SystemEnvironmentPropertySource("env", Map.of(
                                    "CERTPING_CLIENT_IP_SOURCE", "FRONT_DOOR",
                                    "CERTPING_CLIENT_IP_FRONT_DOOR_ID", FDID))))
                    .withUserConfiguration(ClientAddressResolver.class)
                    .run(context -> {
                        ClientAddressResolver resolver = context.getBean(ClientAddressResolver.class);
                        assertThat(resolver.source()).isEqualTo(ClientIpSource.FRONT_DOOR);
                        assertThat(resolver.resolve(viaFrontDoor(FDID, "203.0.113.9"))).isEqualTo("203.0.113.9");
                    });
        }
    }
}
