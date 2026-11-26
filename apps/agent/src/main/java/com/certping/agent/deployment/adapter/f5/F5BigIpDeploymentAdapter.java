// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.f5;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.DeploymentResult;
import com.certping.agent.deployment.adapter.DeploymentAdapter;
import com.certping.agent.deployment.adapter.DeploymentAdapterFor;
import com.certping.agent.deployment.util.CertificateIdentityUtils;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.credential.F5BigIpDeploymentCredential;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * F5 BIG-IP deployment adapter.
 *
 * <p>One credential = one BIG-IP partition. Host, port, partition, and bootstrap profile list
 * all live in the credential scope. Targets are empty.
 *
 * <p>Profile selection on each deploy:
 * <ol>
 *   <li>If prior {@code result.profilesPatched} exists → use those plus rediscover by prior cert ref.</li>
 *   <li>Else if {@code scope.clientSslProfiles} non-empty → use those (bootstrap).</li>
 *   <li>Else if {@code scope.installOnly == true} → install cert/key only, skip binding.</li>
 *   <li>Else → hard-fail with {@code DEPLOY_F5_NO_BOOTSTRAP}.</li>
 * </ol>
 *
 * <p>HA sync is auto-detected via {@code GET /mgmt/tm/cm/device-group}, unless
 * {@code scope.deviceGroup} explicitly overrides.
 */
@Slf4j
@Component
@DeploymentAdapterFor(TargetType.F5_BIGIP)
@RequiredArgsConstructor
public class F5BigIpDeploymentAdapter implements DeploymentAdapter {

    private static final String CTX = "F5 BIG-IP";

    private final SecretStore secretStore;
    private final ObjectMapper objectMapper;
    private final F5BigIpCertRotator rotator;

    @Override
    public DeploymentResult deploy(CertificateBundle bundle, CertDeploymentMessage message) {
        if (message.getDeploymentCredHandle() == null || message.getDeploymentCredHandle().isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_MISSING",
                    "deploymentCredHandle is required for F5_BIGIP deployments");
        }
        String credRaw = secretStore.read(message.getDeploymentCredHandle());
        F5BigIpDeploymentCredential kv = parseKvSecret(credRaw);
        String username = requireField(kv.getUsername(), "username");
        String password = requireField(kv.getPassword(), "password");

        F5Scope scope = parseScope(message.getCredentialScopeJson());
        validateScope(scope);
        F5Targets targets = parseTargets(message.getTargetsJson());

        String host = scope.bigipHost().trim();
        int port = scope.bigipPort() == null ? 443 : scope.bigipPort();
        if (port <= 0 || port > 65535) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "F5 bigipPort out of range: " + port);
        }
        boolean verifySsl = scope.verifySsl() == null || scope.verifySsl();
        boolean installOnly = scope.installOnly() != null && scope.installOnly();
        String partition = scope.partition().trim();

        // Prior result drives version bump and discovery anchor.
        F5Result prior = parsePriorResult(message.getConfigJson());

        String certPem = selectCertificatePem(bundle);
        String keyPem = requirePrivateKey(bundle.privateKey());
        requireUnencryptedKey(keyPem);

        String baseName = sanitizeObjectName(deriveBaseName(targets, prior, message));
        // If operator renamed (new base != prior base), restart version at 1 — a new family.
        // Otherwise bump the prior version. This keeps `{base}_v{n}` semantically clean.
        String priorBase = priorBaseFromCertName(prior);
        int nextVersion = (priorBase != null && !priorBase.equals(baseName)) ? 1 : nextVersion(prior.version());
        String certName = baseName + "_v" + nextVersion;
        String keyName = certName;

        // Build the patch list:
        //  1. prior.profilesPatched (last rotation's known set), else
        //  2. scope.clientSslProfiles (bootstrap), else
        //  3. empty (will install-only or hard-fail in rotator)
        List<String> seedProfiles;
        if (prior.profilesPatched() != null && !prior.profilesPatched().isEmpty()) {
            seedProfiles = new ArrayList<>(prior.profilesPatched());
        } else if (scope.clientSslProfiles() != null && !scope.clientSslProfiles().isEmpty()) {
            seedProfiles = new ArrayList<>(scope.clientSslProfiles());
        } else {
            seedProfiles = List.of();
        }

        // Hostnames for SAN-based first-deploy discovery (third-tier bootstrap fallback).
        // Empty list when leaf PEM can't be parsed — rotator skips SAN discovery in that case.
        List<String> newCertHostnames = CertificateIdentityUtils.extractAllHostnames(bundle.leafCertificate());

        F5BigIpConfig cfg = new F5BigIpConfig(
                host, port, username, password,
                partition, certName, keyName,
                seedProfiles,
                installOnly,
                verifySsl,
                newCertHostnames);

        log.info("F5 BIG-IP deploy: host={}, partition={}, certName={}, installOnly={}, xref={}",
                host, partition, certName, installOnly, message.getCertificateXref());

        F5BigIpCertRotator.RotationResult rot = rotator.rotate(certPem, keyPem, cfg, prior.certName());

        // HA sync — explicit override wins; otherwise auto-detect from rotator's discovery.
        String lastSyncedAt = null;
        List<String> groupsToSync = new ArrayList<>();
        if (scope.deviceGroup() != null && !scope.deviceGroup().isBlank()) {
            groupsToSync.add(scope.deviceGroup().trim());
        } else if (rot.deviceGroups() != null) {
            groupsToSync.addAll(rot.deviceGroups());
        }
        for (String group : groupsToSync) {
            rotator.syncDeviceGroup(cfg, group);
            lastSyncedAt = OffsetDateTime.now(ZoneOffset.UTC).toString();
        }

        String firstTargetResourceId = "f5://" + host + ":" + port
                + "/ltm/profile/client-ssl/" + partition + "/"
                + (rot.profilesPatched().isEmpty() ? certName : rot.profilesPatched().get(0));

        String resultJson = serializeResult(certName, keyName, nextVersion,
                rot.profilesPatched(), lastSyncedAt);
        return DeploymentResult.of(firstTargetResourceId, resultJson);
    }

    // ---------- validation ----------

    void validateScope(F5Scope scope) {
        requireField(scope.bigipHost(), "scope.bigipHost");
        requireField(scope.partition(), "scope.partition");
    }

    // ---------- parsing ----------

    private F5BigIpDeploymentCredential parseKvSecret(String raw) {
        try {
            return objectMapper.readValue(raw, F5BigIpDeploymentCredential.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Invalid F5 BIG-IP KV secret JSON: " + e.getMessage(), e);
        }
    }

    private F5Scope parseScope(String json) {
        if (json == null || json.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " requires credentialScopeJson");
        }
        try {
            return objectMapper.readValue(json, F5Scope.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + CTX + " credentialScopeJson: " + e.getMessage(), e);
        }
    }

    private F5Targets parseTargets(String json) {
        if (json == null || json.isBlank()) {
            return new F5Targets(null);
        }
        try {
            F5Targets parsed = objectMapper.readValue(json, F5Targets.class);
            return parsed == null ? new F5Targets(null) : parsed;
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                    "Failed to parse " + CTX + " targetsJson: " + e.getMessage(), e);
        }
    }

    private F5Result parsePriorResult(String json) {
        if (json == null || json.isBlank()) {
            return F5Result.empty();
        }
        try {
            F5Result parsed = objectMapper.readValue(json, F5Result.class);
            return parsed == null ? F5Result.empty() : parsed;
        } catch (Exception e) {
            log.warn("F5 prior configJson unparseable — treating as first deploy: {}", e.getMessage());
            return F5Result.empty();
        }
    }

    // ---------- helpers ----------

    private static String priorBaseFromCertName(F5Result prior) {
        if (prior == null || prior.certName() == null || prior.certName().isBlank()) return null;
        String stripped = prior.certName().trim().replaceFirst("_v\\d+$", "");
        return stripped.isBlank() ? null : stripped;
    }

    private int nextVersion(Integer priorVersion) {
        if (priorVersion == null || priorVersion < 1) {
            return 1;
        }
        return priorVersion + 1;
    }

    private String selectCertificatePem(CertificateBundle bundle) {
        String fullChain = bundle.fullChain();
        if (fullChain != null && !fullChain.isBlank()) return fullChain.trim();
        String leaf = bundle.leafCertificate();
        if (leaf != null && !leaf.isBlank()) return leaf.trim();
        throw new PermanentAgentException("DEPLOY_CERT_INVALID",
                "Certificate bundle missing leaf/fullChain for F5 BIG-IP deployment");
    }

    private String requirePrivateKey(String keyPem) {
        if (keyPem == null || keyPem.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CERT_INVALID",
                    "Certificate bundle missing private key for F5 BIG-IP deployment");
        }
        return keyPem.trim();
    }

    private void requireUnencryptedKey(String keyPem) {
        String upper = keyPem.toUpperCase(Locale.ROOT);
        if (upper.contains("ENCRYPTED") || upper.contains("PROC-TYPE: 4,ENCRYPTED")) {
            throw new PermanentAgentException("DEPLOY_KEY_ENCRYPTED",
                    "F5 BIG-IP deployment does not support encrypted private keys.");
        }
    }

    private String requireField(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " missing required field: " + name);
        }
        return value.trim();
    }

    /**
     * Resolve the F5 cert object base name. Priority:
     * <ol>
     *   <li>{@code targets.certBaseName} — operator's current intent (supports rename).</li>
     *   <li>Prior {@code result.certName} stripped of {@code _v\d+$} — renewal stability when
     *       targets is blank.</li>
     *   <li>{@code message.certificateXref} — auto-derived per-cert default.</li>
     *   <li>{@code message.domain} fallback.</li>
     *   <li>Hard fallback {@code "cert"}.</li>
     * </ol>
     *
     * <p>If the operator changes {@code targets.certBaseName}, the next deploy starts a new
     * {@code _v1} family under the new base; old {@code _v{n}} cert/key objects on the BIG-IP
     * become orphan once profiles are repointed (or remain bound to the old name if not
     * patched). Operator owns cleanup of the old objects.
     */
    private String deriveBaseName(F5Targets targets, F5Result prior, CertDeploymentMessage message) {
        if (targets != null && targets.certBaseName() != null && !targets.certBaseName().isBlank()) {
            return targets.certBaseName();
        }
        if (prior != null && prior.certName() != null && !prior.certName().isBlank()) {
            String priorBase = prior.certName().trim().replaceFirst("_v\\d+$", "");
            if (!priorBase.isBlank()) return priorBase;
        }
        String xref = message.getCertificateXref();
        if (xref != null && !xref.isBlank()) return xref;
        String domain = message.getDomain();
        if (domain != null && !domain.isBlank()) return domain;
        return "cert";
    }

    private String sanitizeObjectName(String raw) {
        if (raw == null) return "cert";
        String safe = raw.trim()
                .replaceAll("[^A-Za-z0-9_.-]", "-")
                .replaceAll("-+", "-");
        if (safe.length() > 100) safe = safe.substring(0, 100);
        if (safe.isBlank()) {
            throw new PermanentAgentException("DEPLOY_F5_NAME_INVALID",
                    "Derived F5 object name is empty after sanitization");
        }
        return safe;
    }

    private String serializeResult(String certName, String keyName, int version,
                                   List<String> profilesPatched, String lastSyncedAt) {
        try {
            Map<String, Object> root = new LinkedHashMap<>();
            root.put("certName", certName);
            root.put("keyName", keyName);
            root.put("version", version);
            root.put("profilesPatched", profilesPatched == null ? List.of() : profilesPatched);
            if (lastSyncedAt != null) {
                root.put("lastSyncedAt", lastSyncedAt);
            }
            return objectMapper.writeValueAsString(root);
        } catch (Exception e) {
            log.warn("Failed to serialize F5 result — returning null: {}", e.getMessage());
            return null;
        }
    }
}
