// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.messaging.transport.AgentGatewayHeaders;
import com.certmanagement.messaging.transport.AgentTokenService;
import com.certmanagement.messaging.transport.AgentTokenService.AgentToken;
import com.certmanagement.security.OrgResolver;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.info.BuildProperties;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static com.certmanagement.security.Permissions.ROLE_ORGANIZATION_ADMIN;
import static com.certmanagement.security.Permissions.ROLE_SUPER_ADMIN;

/**
 * "Add agent": creates the token an agent uses to connect, and the command to start it.
 *
 * <p>Org admins manage their own organization's tokens; super admins pass {@code organizationId}.
 */
@RestController
@RequestMapping("/api/v1/agent-tokens")
@PreAuthorize("hasRole('" + ROLE_SUPER_ADMIN + "') or hasRole('" + ROLE_ORGANIZATION_ADMIN + "')")
@Tag(name = "Agent Tokens", description = "Create, list and revoke the tokens agents connect with")
public class AgentTokenController {

    /** Agent image tag when the server does not know its own release version. */
    static final String FALLBACK_AGENT_VERSION = "0.0.1-beta";
    static final String AGENT_IMAGE = "ghcr.io/certping-labs/certping-agent";
    private static final Pattern RELEASE_TAG = Pattern.compile("[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.]+)?");

    private final AgentTokenService tokens;
    private final String agentVersion;

    public AgentTokenController(AgentTokenService tokens,
                                ObjectProvider<BuildProperties> buildProperties,
                                @Value("${certping.version:}") String configuredVersion) {
        this.tokens = tokens;
        this.agentVersion = agentVersion(configuredVersion,
                buildProperties == null ? null : buildProperties.getIfAvailable());
    }

    /**
     * The release this server runs, which is the agent image to start beside it: certping.version
     * (CERTPING_VERSION, set by the release image), then the jar's build-info, then 0.0.1-beta. Values
     * that name no published image (dev, latest, a SNAPSHOT) are skipped.
     */
    static String agentVersion(String configuredVersion, BuildProperties build) {
        String configured = releaseTag(configuredVersion);
        if (configured != null) {
            return configured;
        }
        String built = build == null ? null : releaseTag(build.getVersion());
        return built != null ? built : FALLBACK_AGENT_VERSION;
    }

    private static String releaseTag(String version) {
        if (version == null) {
            return null;
        }
        String tag = version.trim();
        if (tag.startsWith("v")) {
            tag = tag.substring(1);
        }
        return RELEASE_TAG.matcher(tag).matches() && !tag.contains("SNAPSHOT") ? tag : null;
    }

    /**
     * @param expiresInDays optional: the token stops working this many days from now (1 to 3650).
     *                      Absent, it never expires, as before.
     */
    public record CreateRequest(String name, String serverUrl, Integer expiresInDays) {
        public CreateRequest(String name, String serverUrl) {
            this(name, serverUrl, null);
        }
    }

    static final int MAX_EXPIRES_IN_DAYS = 3650;

    @GetMapping
    @Operation(summary = "Lists an organization's agent tokens (never the token values)")
    public List<AgentToken> list(@RequestParam(value = "organizationId", required = false) Long organizationId) {
        return tokens.list(OrgResolver.resolve(organizationId));
    }

    @PostMapping
    @Operation(summary = "Creates an agent token. The value is returned once and cannot be read again.")
    public ResponseEntity<Map<String, Object>> create(
            @RequestParam(value = "organizationId", required = false) Long organizationId,
            @RequestBody(required = false) CreateRequest request) {
        Long orgId = OrgResolver.resolve(organizationId);
        String name = request == null || request.name() == null || request.name().isBlank()
                ? "agent" : request.name().trim();
        if (name.length() > 100) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "name must be at most 100 characters");
        }
        Integer days = request == null ? null : request.expiresInDays();
        if (days != null && (days < 1 || days > MAX_EXPIRES_IN_DAYS)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "expiresInDays must be between 1 and " + MAX_EXPIRES_IN_DAYS);
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String createdBy = auth == null ? null : auth.getName();
        AgentTokenService.CreatedToken created = days == null
                ? tokens.create(orgId, name, createdBy)
                : tokens.create(orgId, name, createdBy, OffsetDateTime.now(ZoneOffset.UTC).plusDays(days));

        String serverUrl = request == null || request.serverUrl() == null || request.serverUrl().isBlank()
                ? "https://<your-certping-host>" : request.serverUrl().trim();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("token", created.token());
        body.put("value", created.plainToken());
        body.put("gatewayPath", AgentGatewayHeaders.BASE_PATH);
        body.put("dockerCommand", dockerCommand(serverUrl, created.plainToken(), agentVersion));
        return ResponseEntity.status(HttpStatus.CREATED).body(body);
    }

    /**
     * The command that starts an agent with this token, on the image of this server's release.
     * Private keys stay in the agent's own network, so it names a cloud secret manager to fill in
     * (AWS_SM with AWS_REGION and GCP_SM with GCP_PROJECT_ID work the same way); LOCAL is only for
     * the bundled agent, which shares the server's secret volume.
     */
    static String dockerCommand(String serverUrl, String token, String agentVersion) {
        return String.join(" \\\n  ",
                "docker run -d --name certping-agent --restart unless-stopped",
                "-e SPRING_PROFILES_ACTIVE=selfhosted",
                "-e CERTPING_SERVER_URL=" + serverUrl,
                "-e CERTPING_AGENT_TOKEN=" + token,
                "-e AGENT_SECRET_STORE_PROVIDER=AZURE_KV -e CLIENT_KV_URI=https://<your-vault>.vault.azure.net",
                AGENT_IMAGE + ":" + agentVersion);
    }

    @DeleteMapping("/{tokenId}")
    @Operation(summary = "Revokes an agent token; the agent using it stops being able to connect")
    public ResponseEntity<Void> revoke(@PathVariable long tokenId,
                                       @RequestParam(value = "organizationId", required = false) Long organizationId) {
        Long orgId = OrgResolver.resolve(organizationId);
        if (!tokens.revoke(orgId, tokenId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "token not found or already revoked");
        }
        return ResponseEntity.noContent().build();
    }
}
