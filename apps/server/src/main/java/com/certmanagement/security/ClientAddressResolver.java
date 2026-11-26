// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.utils.NetworkAddresses;
import com.google.common.net.InetAddresses;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Enumeration;
import java.util.regex.Pattern;

/**
 * Who the client of a request is: the one place that reads client addresses from a request. Audit rows
 * (through {@link com.certmanagement.interceptor.RequestContextInterceptor}), and
 * authentication-failure logs all take it from here.
 *
 * <p>The leftmost {@code X-Forwarded-For} entry is whatever the client wrote and is never read. What is
 * believed depends on {@code certping.client-ip.source}, see {@link ClientIpSource}: by default only the
 * entry the nearest proxy appended, and only when the socket peer is a private or loopback address.
 * {@code X-Azure-FDID} is not a secret: {@code FRONT_DOOR} holds only while the service cannot be reached
 * around Azure Front Door.
 *
 * <p>In Kubernetes Spring Boot turns on Tomcat's {@code RemoteIpValve}, which runs before this class:
 * {@link HttpServletRequest#getRemoteAddr()} is already the rightmost {@code X-Forwarded-For} entry
 * that is not a private address (or the leftmost one, when all are private), and the entries it used
 * are gone from the header. {@code LAST_PROXY_HOP} gives the same answer with the valve on or off.
 * {@code PEER} returns whatever the valve left in {@code getRemoteAddr()}, so in Kubernetes it is the
 * valve's choice, not the socket peer. The valve is left on on purpose: OAuth2/OIDC redirect URIs
 * depend on its {@code X-Forwarded-Proto} handling.
 *
 * <p>Behind a Kubernetes load balancer with {@code externalTrafficPolicy: Cluster}, every client is
 * source-NATed to a node IP before the ingress sees it. The real client address never reaches this service
 * then, so every mode records a node IP; {@code externalTrafficPolicy: Local} changes that.
 *
 * <p>Every answer is a canonical IP literal ({@code ::ffff:a.b.c.d} becomes {@code a.b.c.d}, IPv6 is
 * compressed and lowercase, ports, brackets and zones are dropped), or {@code null} when no address
 * could be read, so a forged header cannot put arbitrary text into a row.
 */
@Slf4j
@Component
public class ClientAddressResolver {

    static final String FRONT_DOOR_CLIENT_IP = "X-Azure-ClientIP";
    static final String FRONT_DOOR_ID = "X-Azure-FDID";
    static final String FORWARDED_FOR = "X-Forwarded-For";

    /** Longer than any address with brackets, zone and port that is worth reading. */
    static final int MAX_ADDRESS_LENGTH = 64;

    private static final Pattern PORT = Pattern.compile(":\\d{1,5}");

    private final ClientIpSource source;
    private final byte[] frontDoorId;

    @Autowired
    public ClientAddressResolver(@Value("${certping.client-ip.source:LAST_PROXY_HOP}") String source,
                                 @Value("${certping.client-ip.front-door-id:}") String frontDoorId) {
        this(ClientIpSource.parse(source), frontDoorId);
    }

    public ClientAddressResolver(ClientIpSource source, String frontDoorId) {
        this.source = source;
        this.frontDoorId = frontDoorId == null || frontDoorId.isBlank()
                ? null : frontDoorId.trim().getBytes(StandardCharsets.UTF_8);
        if (source == ClientIpSource.FRONT_DOOR && this.frontDoorId == null) {
            log.warn("[CLIENT_IP] certping.client-ip.source=FRONT_DOOR without certping.client-ip.front-door-id:"
                    + " X-Azure-ClientIP is never believed and every request falls back to LAST_PROXY_HOP");
        } else {
            log.info("[CLIENT_IP] source={} frontDoorId={}", source, this.frontDoorId == null ? "unset" : "set");
        }
    }

    public ClientIpSource source() {
        return source;
    }

    /** The client's address, or {@code null} when none could be read. */
    public String resolve(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        InetAddress client = switch (source) {
            case FRONT_DOOR -> frontDoor(request);
            case LAST_PROXY_HOP -> lastProxyHop(request);
            case PEER -> parse(request.getRemoteAddr());
        };
        return client == null ? null : InetAddresses.toAddrString(client);
    }

    private InetAddress frontDoor(HttpServletRequest request) {
        if (viaFrontDoor(request)) {
            InetAddress client = parse(request.getHeader(FRONT_DOOR_CLIENT_IP));
            if (client != null) {
                return client;
            }
        }
        return lastProxyHop(request);
    }

    private boolean viaFrontDoor(HttpServletRequest request) {
        String got = request.getHeader(FRONT_DOOR_ID);
        return frontDoorId != null && got != null
                && MessageDigest.isEqual(got.trim().getBytes(StandardCharsets.UTF_8), frontDoorId);
    }

    private static InetAddress lastProxyHop(HttpServletRequest request) {
        InetAddress peer = parse(request.getRemoteAddr());
        if (peer == null || !NetworkAddresses.isNonPublic(peer)) {
            return peer;
        }
        InetAddress hop = parse(rightmostForwardedFor(request));
        return hop != null ? hop : peer;
    }

    /** The last entry of the last {@code X-Forwarded-For} header: the one the nearest proxy appended. */
    private static String rightmostForwardedFor(HttpServletRequest request) {
        String last = null;
        Enumeration<String> headers = request.getHeaders(FORWARDED_FOR);
        while (headers != null && headers.hasMoreElements()) {
            String value = headers.nextElement();
            if (value != null && !value.isBlank()) {
                last = value;
            }
        }
        return last == null ? null : last.substring(last.lastIndexOf(',') + 1);
    }

    /** {@code raw} as an address, or {@code null} unless it is an IP literal, optionally with a port, IPv6 brackets or a zone. */
    private static InetAddress parse(String raw) {
        if (raw == null) {
            return null;
        }
        String text = raw.trim();
        if (text.isEmpty() || text.length() > MAX_ADDRESS_LENGTH) {
            return null;
        }
        if (text.startsWith("[")) {
            int close = text.indexOf(']');
            if (close < 0 || !isPortOrEmpty(text.substring(close + 1))) {
                return null;
            }
            text = text.substring(1, close);
        } else {
            int colon = text.indexOf(':');
            // One colon is an IPv4 address and a port; IPv6 has at least two.
            if (colon >= 0 && colon == text.lastIndexOf(':')) {
                if (!isPortOrEmpty(text.substring(colon))) {
                    return null;
                }
                text = text.substring(0, colon);
            }
        }
        int zone = text.indexOf('%');
        if (zone >= 0) {
            text = text.substring(0, zone);
        }
        try {
            // Never a DNS lookup: Guava parses literals only. A mapped IPv4 address comes back as IPv4.
            return InetAddresses.forString(text);
        } catch (IllegalArgumentException notAnAddress) {
            return null;
        }
    }

    private static boolean isPortOrEmpty(String rest) {
        return rest.isEmpty() || PORT.matcher(rest).matches();
    }
}
