// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.api.gax.rpc.AlreadyExistsException;
import com.google.api.gax.rpc.ApiException;
import com.google.api.gax.rpc.FailedPreconditionException;
import com.google.api.gax.rpc.InvalidArgumentException;
import com.google.api.gax.rpc.NotFoundException;
import com.google.cloud.certificatemanager.v1.Certificate;
import com.google.cloud.certificatemanager.v1.CertificateManagerClient;
import com.google.cloud.certificatemanager.v1.CertificateManagerSettings;
import com.google.cloud.certificatemanager.v1.CertificateMapEntry;
import com.google.cloud.certificatemanager.v1.CertificateMapEntryName;
import com.google.cloud.certificatemanager.v1.CertificateMapName;
import com.google.cloud.certificatemanager.v1.LocationName;
import com.google.cloud.certificatemanager.v1.UpdateCertificateMapEntryRequest;
import com.google.cloud.certificatemanager.v1.UpdateCertificateRequest;
import com.google.protobuf.FieldMask;
import com.google.auth.oauth2.GoogleCredentials;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Component
public class GcpCertificateManagerService {

    public String createCertificate(String projectId,
                                    String location,
                                    String certificateId,
                                    CertificateBundle bundle,
                                    GoogleCredentials credentials) {
        String certPem = selectCertificatePem(bundle);
        String keyPem = requirePrivateKey(bundle.privateKey());

        Certificate cert = Certificate.newBuilder()
                .setSelfManaged(Certificate.SelfManagedCertificate.newBuilder()
                        .setPemCertificate(certPem)
                        .setPemPrivateKey(keyPem)
                        .build())
                .build();

        try (CertificateManagerClient client = CertificateManagerClient.create(
                CertificateManagerSettings.newBuilder()
                        .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                        .build())) {

            LocationName parent = LocationName.of(projectId, location);
            Certificate created = client.createCertificateAsync(parent, cert, certificateId).get();
            String name = created.getName();
            if (name == null || name.isBlank()) {
                throw new PermanentAgentException("DEPLOY_RESULT_NULL_RESOURCE_ID",
                        "Certificate Manager createCertificate returned empty resource name");
            }
            return name;

        } catch (AlreadyExistsException e) {
            // Idempotent retry: the resource already exists (e.g. a scheduled retry after a partial
            // success, or a re-triggered issuance). Update the PEM/key in place instead of failing —
            // GCP requires the SANs to match. This is what lets the new scheduled-retry flow actually
            // succeed on a re-run rather than dead-lettering on ALREADY_EXISTS.
            String existingName = LocationName.of(projectId, location).toString()
                    + "/certificates/" + certificateId;
            log.info("Certificate Manager certificate {} already exists — updating in place (idempotent)", existingName);
            if (updateCertificate(existingName, bundle, credentials)) {
                return existingName;
            }
            throw new PermanentAgentException("DEPLOY_RESOURCE_CONFLICT",
                    "Certificate Manager resource '" + certificateId + "' exists with incompatible SANs — "
                            + "manual cleanup needed", e);
        } catch (PermanentAgentException e) {
            throw e;
        } catch (Exception e) {
            if (e instanceof ApiException ae) {
                Optional<RateLimitClassifier.RateLimitVerdict> rl =
                        RateLimitClassifier.fromGcp(ae, "DEPLOY_PROVIDER_THROTTLED");
                if (rl.isPresent()) {
                    throw rl.get().toRetryable("gcp certificate-manager create", certificateId, e);
                }
            }
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("gcp certificate-manager create", certificateId, e);
            }
            throw new PermanentAgentException("DEPLOY_GCP_CERT_MANAGER_FAILED",
                    "Certificate Manager createCertificate failed: " + e.getMessage(), e);
        }
    }

    /**
     * Replace the PEM cert + key on an existing self-managed Certificate resource. GCP requires
     * the new cert's SAN list to exactly match the existing cert's SANs.
     *
     * @return {@code true} if updated in place; {@code false} if GCP rejected the update because
     *         the resource is missing or the SANs don't match (caller should fall back to creating
     *         a new versioned resource and repointing references).
     * @throws PermanentAgentException for any other failure
     */
    public boolean updateCertificate(String resourceName,
                                     CertificateBundle bundle,
                                     GoogleCredentials credentials) {
        if (resourceName == null || resourceName.isBlank()) {
            return false;
        }
        String certPem = selectCertificatePem(bundle);
        String keyPem = requirePrivateKey(bundle.privateKey());

        Certificate updated = Certificate.newBuilder()
                .setName(resourceName)
                .setSelfManaged(Certificate.SelfManagedCertificate.newBuilder()
                        .setPemCertificate(certPem)
                        .setPemPrivateKey(keyPem)
                        .build())
                .build();

        FieldMask mask = FieldMask.newBuilder()
                .addPaths("self_managed")
                .build();

        try (CertificateManagerClient client = CertificateManagerClient.create(
                CertificateManagerSettings.newBuilder()
                        .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                        .build())) {

            client.updateCertificateAsync(
                    UpdateCertificateRequest.newBuilder()
                            .setCertificate(updated)
                            .setUpdateMask(mask)
                            .build()).get();
            log.info("Certificate Manager updateCertificate succeeded: {}", resourceName);
            return true;

        } catch (NotFoundException | InvalidArgumentException | FailedPreconditionException e) {
            log.warn("Certificate Manager updateCertificate rejected ({}): falling back to create-new for {}",
                    e.getClass().getSimpleName(), resourceName);
            return false;
        } catch (Exception e) {
            if (e instanceof ApiException ae) {
                Optional<RateLimitClassifier.RateLimitVerdict> rlt =
                        RateLimitClassifier.fromGcp(ae, "DEPLOY_PROVIDER_THROTTLED");
                if (rlt.isPresent()) {
                    throw rlt.get().toRetryable("gcp certificate-manager update", resourceName, e);
                }
            }
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("gcp certificate-manager update", resourceName, e);
            }
            Throwable cause = e.getCause();
            if (cause instanceof NotFoundException
                    || cause instanceof InvalidArgumentException
                    || cause instanceof FailedPreconditionException) {
                log.warn("Certificate Manager updateCertificate rejected ({}): falling back to create-new for {}",
                        cause.getClass().getSimpleName(), resourceName);
                return false;
            }
            throw new PermanentAgentException("DEPLOY_GCP_CERT_UPDATE_FAILED",
                    "Certificate Manager updateCertificate failed: " + e.getMessage(), e);
        }
    }

    /**
     * Best-effort delete of a superseded Certificate resource. Logs and swallows all errors — the
     * caller has already repointed references away from this resource, so leaving it behind is
     * non-fatal (operators can clean up later, or it'll be retried on the next rotation).
     */
    public void deleteCertificate(String resourceName, GoogleCredentials credentials) {
        if (resourceName == null || resourceName.isBlank()) {
            return;
        }
        try (CertificateManagerClient client = CertificateManagerClient.create(
                CertificateManagerSettings.newBuilder()
                        .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                        .build())) {

            client.deleteCertificateAsync(resourceName).get();
            log.info("Certificate Manager deleteCertificate succeeded: {}", resourceName);

        } catch (NotFoundException e) {
            log.info("Certificate Manager deleteCertificate: resource already gone: {}", resourceName);
        } catch (Exception e) {
            Throwable cause = e.getCause();
            if (cause instanceof NotFoundException) {
                log.info("Certificate Manager deleteCertificate: resource already gone: {}", resourceName);
                return;
            }
            log.warn("Certificate Manager deleteCertificate failed (best-effort, ignoring): name={}, error={}",
                    resourceName, e.getMessage());
        }
    }

    /**
     * List every {@link CertificateMapEntry} on the given map, keyed by its literal
     * {@code hostname} field (e.g. {@code "*.example.com"}, {@code "api.example.com"}).
     * The value is the full entry resource name so callers can update by name without
     * needing the entry's id separately. Hostname keys are normalized via
     * {@code String#trim} + lowercase to make lookup robust to operator-side casing.
     */
    public Map<String, String> listEntriesByHostname(String projectId,
                                                     String location,
                                                     String mapName,
                                                     GoogleCredentials credentials) {
        if (mapName == null || mapName.isBlank()) {
            return Map.of();
        }
        Map<String, String> out = new LinkedHashMap<>();
        try (CertificateManagerClient client = CertificateManagerClient.create(
                CertificateManagerSettings.newBuilder()
                        .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                        .build())) {

            CertificateMapName parent = CertificateMapName.of(projectId, location, mapName);
            for (CertificateMapEntry entry : client.listCertificateMapEntries(parent).iterateAll()) {
                String hostname = entry.getHostname();
                if (hostname == null || hostname.isBlank()) continue;
                out.put(hostname.trim().toLowerCase(), entry.getName());
            }
            return out;
        } catch (NotFoundException e) {
            log.warn("Certificate Manager map not found while listing entries: project={}, location={}, map={}",
                    projectId, location, mapName);
            return Map.of();
        } catch (Exception e) {
            if (e instanceof ApiException ae) {
                Optional<RateLimitClassifier.RateLimitVerdict> rlt =
                        RateLimitClassifier.fromGcp(ae, "DEPLOY_PROVIDER_THROTTLED");
                if (rlt.isPresent()) {
                    throw rlt.get().toRetryable("gcp certificate-manager list-entries", mapName, e);
                }
            }
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("gcp certificate-manager list-entries", mapName, e);
            }
            throw new PermanentAgentException("DEPLOY_GCP_CERT_MAP_FAILED",
                    "Certificate Manager listCertificateMapEntries failed: " + e.getMessage(), e);
        }
    }

    /**
     * Update an existing {@link CertificateMapEntry} (located by its full resource name) to
     * point at the given certificate resource. Used when an entry already exists for a
     * given hostname and we just need to repoint its {@code certificates[]}.
     */
    public String updateMapEntryCertificates(String entryFullResourceName,
                                             String certificateResourceName,
                                             GoogleCredentials credentials) {
        try (CertificateManagerClient client = CertificateManagerClient.create(
                CertificateManagerSettings.newBuilder()
                        .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                        .build())) {

            CertificateMapEntry updated = CertificateMapEntry.newBuilder()
                    .setName(entryFullResourceName)
                    .addAllCertificates(List.of(certificateResourceName))
                    .build();

            FieldMask mask = FieldMask.newBuilder().addPaths("certificates").build();

            CertificateMapEntry result = client.updateCertificateMapEntryAsync(
                    UpdateCertificateMapEntryRequest.newBuilder()
                            .setCertificateMapEntry(updated)
                            .setUpdateMask(mask)
                            .build()).get();
            return result.getName();

        } catch (Exception e) {
            if (e instanceof ApiException ae) {
                Optional<RateLimitClassifier.RateLimitVerdict> rlt =
                        RateLimitClassifier.fromGcp(ae, "DEPLOY_PROVIDER_THROTTLED");
                if (rlt.isPresent()) {
                    throw rlt.get().toRetryable("gcp certificate-manager update-entry", entryFullResourceName, e);
                }
            }
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("gcp certificate-manager update-entry", entryFullResourceName, e);
            }
            throw new PermanentAgentException("DEPLOY_GCP_CERT_MAP_FAILED",
                    "Certificate Manager updateCertificateMapEntry failed: " + e.getMessage(), e);
        }
    }

    /**
     * Create a new {@link CertificateMapEntry} with the given id, hostname, and certificate.
     * Returns the full entry resource name. Throws if an entry with that id already exists —
     * the caller is responsible for the list-by-hostname check beforehand.
     */
    public String createMapEntry(String projectId,
                                 String location,
                                 String mapName,
                                 String entryId,
                                 String hostname,
                                 String certificateResourceName,
                                 GoogleCredentials credentials) {
        CertificateMapName parent = CertificateMapName.of(projectId, location, mapName);
        try (CertificateManagerClient client = CertificateManagerClient.create(
                CertificateManagerSettings.newBuilder()
                        .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                        .build())) {

            CertificateMapEntry entry = CertificateMapEntry.newBuilder()
                    .setHostname(hostname)
                    .addAllCertificates(List.of(certificateResourceName))
                    .build();

            CertificateMapEntry created = client.createCertificateMapEntryAsync(parent, entry, entryId).get();
            return created.getName();

        } catch (PermanentAgentException e) {
            throw e;
        } catch (Exception e) {
            if (e instanceof ApiException ae) {
                Optional<RateLimitClassifier.RateLimitVerdict> rlt =
                        RateLimitClassifier.fromGcp(ae, "DEPLOY_PROVIDER_THROTTLED");
                if (rlt.isPresent()) {
                    throw rlt.get().toRetryable("gcp certificate-manager create-entry", entryId, e);
                }
            }
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("gcp certificate-manager create-entry", entryId, e);
            }
            throw new PermanentAgentException("DEPLOY_GCP_CERT_MAP_FAILED",
                    "Certificate Manager createCertificateMapEntry failed: " + e.getMessage(), e);
        }
    }

    public String upsertCertificateMapEntry(String projectId,
                                            String location,
                                            String mapName,
                                            String entryId,
                                            String hostname,
                                            String certificateResourceName,
                                            GoogleCredentials credentials) {
        if (mapName == null || mapName.isBlank()) {
            return null;
        }

        String resolvedEntryId = entryId == null || entryId.isBlank()
                ? GcpNameUtils.toResourceId(hostname, "certping-entry")
                : entryId.trim();

        CertificateMapName parent = CertificateMapName.of(projectId, location, mapName);

        try (CertificateManagerClient client = CertificateManagerClient.create(
                CertificateManagerSettings.newBuilder()
                        .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                        .build())) {

            CertificateMapEntry entry = CertificateMapEntry.newBuilder()
                    .setHostname(hostname)
                    .addAllCertificates(List.of(certificateResourceName))
                    .build();

            CertificateMapEntry created = client.createCertificateMapEntryAsync(
                    parent, entry, resolvedEntryId).get();
            return created.getName();

        } catch (AlreadyExistsException e) {
            return updateCertificateMapEntry(projectId, location, mapName, resolvedEntryId,
                    hostname, certificateResourceName, credentials);
        } catch (PermanentAgentException e) {
            throw e;
        } catch (Exception e) {
            if (e instanceof ApiException ae) {
                Optional<RateLimitClassifier.RateLimitVerdict> rlt =
                        RateLimitClassifier.fromGcp(ae, "DEPLOY_PROVIDER_THROTTLED");
                if (rlt.isPresent()) {
                    throw rlt.get().toRetryable("gcp certificate-manager upsert-entry", resolvedEntryId, e);
                }
            }
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("gcp certificate-manager upsert-entry", resolvedEntryId, e);
            }
            throw new PermanentAgentException("DEPLOY_GCP_CERT_MAP_FAILED",
                    "Certificate Manager createCertificateMapEntry failed: " + e.getMessage(), e);
        }
    }

    private String updateCertificateMapEntry(String projectId,
                                             String location,
                                             String mapName,
                                             String entryId,
                                             String hostname,
                                             String certificateResourceName,
                                             GoogleCredentials credentials) {
        try (CertificateManagerClient client = CertificateManagerClient.create(
                CertificateManagerSettings.newBuilder()
                        .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                        .build())) {

            CertificateMapEntryName entryName = CertificateMapEntryName.of(projectId, location, mapName, entryId);
            CertificateMapEntry updated = CertificateMapEntry.newBuilder()
                    .setName(entryName.toString())
                    .setHostname(hostname)
                    .addAllCertificates(List.of(certificateResourceName))
                    .build();

            FieldMask mask = FieldMask.newBuilder()
                    .addPaths("certificates")
                    .addPaths("hostname")
                    .build();

            CertificateMapEntry result = client.updateCertificateMapEntryAsync(
                    UpdateCertificateMapEntryRequest.newBuilder()
                            .setCertificateMapEntry(updated)
                            .setUpdateMask(mask)
                            .build()).get();

            return result.getName();

        } catch (Exception e) {
            if (e instanceof ApiException ae) {
                Optional<RateLimitClassifier.RateLimitVerdict> rlt =
                        RateLimitClassifier.fromGcp(ae, "DEPLOY_PROVIDER_THROTTLED");
                if (rlt.isPresent()) {
                    throw rlt.get().toRetryable("gcp certificate-manager update-entry", entryId, e);
                }
            }
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("gcp certificate-manager update-entry", entryId, e);
            }
            throw new PermanentAgentException("DEPLOY_GCP_CERT_MAP_FAILED",
                    "Certificate Manager updateCertificateMapEntry failed: " + e.getMessage(), e);
        }
    }

    private String selectCertificatePem(CertificateBundle bundle) {
        if (bundle.fullChain() != null && !bundle.fullChain().isBlank()) {
            return bundle.fullChain();
        }
        return bundle.leafCertificate();
    }

    private String requirePrivateKey(String keyPem) {
        if (keyPem == null || keyPem.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CERT_INVALID",
                    "Certificate bundle missing private key for GCP deployment");
        }
        return keyPem;
    }
}
