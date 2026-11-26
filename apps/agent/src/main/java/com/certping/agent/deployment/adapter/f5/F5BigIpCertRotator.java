// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.f5;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class F5BigIpCertRotator {

    private static final int UPLOAD_CHUNK_SIZE_BYTES = 512 * 1024;

    private final ObjectMapper objectMapper;

    /**
     * Result of a rotation: the profiles actually patched and the device groups detected for HA.
     */
    public record RotationResult(List<String> profilesPatched, List<String> deviceGroups) {}

    /**
     * Uploads cert/key, installs the TMSH cert/key objects in {@code cfg.partition()}, optionally
     * patches client-SSL profiles, saves config, and detects HA device groups for the adapter to
     * sync afterward. The token is deleted in a finally block to avoid F5's 100-token-per-user cap.
     *
     * @param priorCertName  if non-null, the rotator additionally discovers any client-SSL profile
     *                       still bound to {@code /partition/priorCertName} and patches it (covers
     *                       SNI multi-profile setups where operators added profiles after bootstrap).
     */
    public RotationResult rotate(String certPem, String keyPem, F5BigIpConfig cfg, String priorCertName) {
        F5BigIpAuthClient auth = new F5BigIpAuthClient(
                objectMapper,
                cfg.bigipHost(),
                cfg.bigipPort(),
                cfg.username(),
                cfg.password(),
                cfg.verifySsl());
        F5BigIpRestClient client = new F5BigIpRestClient(objectMapper, auth);

        String certFilename = cfg.certName() + ".crt";
        String keyFilename = cfg.keyName() + ".key";

        try {
            // 1. chunked upload (idempotent — F5 overwrites by filename)
            client.uploadFileChunked(certFilename,
                    certPem.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    UPLOAD_CHUNK_SIZE_BYTES);
            client.uploadFileChunked(keyFilename,
                    keyPem.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    UPLOAD_CHUNK_SIZE_BYTES);

            // 2. install cert/key TMSH objects
            client.installCertObject(cfg.certName(), certFilename);
            client.installKeyObject(cfg.keyName(), keyFilename);

            List<String> profilesPatched = List.of();

            if (cfg.installOnly()) {
                log.info("F5 install-only mode: skipping profile binding (cert/key installed in partition={})",
                        cfg.partition());
            } else {
                // 3. union of (declared profiles) + (profiles still using the prior cert)
                java.util.LinkedHashSet<String> toPatch = new java.util.LinkedHashSet<>();
                if (cfg.clientSslProfiles() != null) toPatch.addAll(cfg.clientSslProfiles());
                if (priorCertName != null && !priorCertName.isBlank()) {
                    List<String> discovered = client.findProfilesUsingCert(cfg.partition(), priorCertName);
                    if (!discovered.isEmpty()) {
                        log.info("F5 discovered {} profile(s) using prior cert '{}' in partition={}",
                                discovered.size(), priorCertName, cfg.partition());
                        toPatch.addAll(discovered);
                    }
                }
                // Third-tier first-deploy fallback: SAN-based discovery. When operator hasn't
                // configured clientSslProfiles and there's no prior cert to filter on, walk the
                // partition and match profiles whose bound cert's CN/SANs overlap with the new
                // cert's identity (wildcard semantics in either direction).
                if (toPatch.isEmpty() && cfg.newCertHostnames() != null && !cfg.newCertHostnames().isEmpty()) {
                    List<String> sanDiscovered = client.findProfilesByCertHostnames(
                            cfg.partition(), cfg.newCertHostnames());
                    if (!sanDiscovered.isEmpty()) {
                        log.info("F5 SAN-based discovery: matched {} profile(s) by hostname overlap "
                                        + "in partition={} (hostnames={})",
                                sanDiscovered.size(), cfg.partition(), cfg.newCertHostnames());
                        toPatch.addAll(sanDiscovered);
                    }
                }
                if (toPatch.isEmpty()) {
                    throw new PermanentAgentException("DEPLOY_F5_NO_BOOTSTRAP",
                            "F5 first deploy requires either scope.clientSslProfiles or scope.installOnly=true, "
                                    + "OR an existing client-SSL profile in partition '" + cfg.partition()
                                    + "' whose bound cert covers one of " + cfg.newCertHostnames() + ". "
                                    + "Provide a profile list, set installOnly=true, or pre-bind a profile and re-run.");
                }

                for (String profile : toPatch) {
                    client.patchClientSslProfile(cfg.partition(), profile, cfg.certName(), cfg.keyName());
                    log.debug("F5 profile patched: partition={}, profile={}, certName={}",
                            cfg.partition(), profile, cfg.certName());
                }
                profilesPatched = new java.util.ArrayList<>(toPatch);
            }

            // 4. save running config to disk (in-memory until saved; reboot reverts otherwise)
            client.saveConfig();

            // 5. detect HA device groups for the adapter to sync (auto-detection)
            List<String> deviceGroups = client.detectDeviceGroups();

            log.info("F5 BIG-IP rotation complete: host={}, partition={}, certName={}, profilesPatched={}, hadDeviceGroups={}",
                    cfg.bigipHost(), cfg.partition(), cfg.certName(), profilesPatched.size(), !deviceGroups.isEmpty());

            return new RotationResult(profilesPatched, deviceGroups);

        } catch (PermanentAgentException | TransientAgentException | RetryableAgentException e) {
            throw e;
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_F5_FAILED",
                    "F5 BIG-IP rotation failed for partition " + cfg.partition() + ": " + e.getMessage(), e);
        } finally {
            // Free the token slot — F5 caps active tokens at 100 per user.
            auth.logout();
        }
    }

    /** Triggers HA sync to a device-group and polls for completion. */
    public void syncDeviceGroup(F5BigIpConfig cfg, String deviceGroup) {
        F5BigIpAuthClient auth = new F5BigIpAuthClient(
                objectMapper, cfg.bigipHost(), cfg.bigipPort(),
                cfg.username(), cfg.password(), cfg.verifySsl());
        F5BigIpRestClient client = new F5BigIpRestClient(objectMapper, auth);
        try {
            client.syncToDeviceGroup(deviceGroup);
            client.pollSyncStatus();
            log.info("F5 BIG-IP HA sync complete: host={}, deviceGroup={}", cfg.bigipHost(), deviceGroup);
        } catch (PermanentAgentException | TransientAgentException | RetryableAgentException e) {
            throw e;
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_F5_SYNC_FAILED",
                    "F5 device-group sync failed: " + e.getMessage(), e);
        } finally {
            auth.logout();
        }
    }
}
