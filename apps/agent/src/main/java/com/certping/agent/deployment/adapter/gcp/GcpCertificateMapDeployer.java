// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.util.CertificateIdentityUtils;
import com.certping.agent.exception.PermanentAgentException;
import com.google.auth.oauth2.GoogleCredentials;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deploys a certificate into a Certificate Manager certificate map: uploads it as a self-managed
 * certificate and points the map entry of each of its hostnames at it.
 *
 * <p>Used by the {@code GCP_CERT_MANAGER} target, and by the target-proxy targets when the proxy
 * serves certificates from a map, because GCP ignores a proxy's {@code sslCertificates} while a
 * map is attached.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class GcpCertificateMapDeployer {

    private static final Pattern MAP_NAME = Pattern.compile(
            "projects/([^/]+)/locations/([^/]+)/certificateMaps/([^/]+)$");

    private final GcpCertificateManagerService certificateManagerService;

    public record AppliedEntry(String hostname, String certificateMapEntry, String action) {}

    public record MapDeployment(String certificateResourceName, String certificateMap,
                                List<AppliedEntry> appliedEntries) {}

    /**
     * Deploys into the map a target proxy references, e.g.
     * {@code //certificatemanager.googleapis.com/projects/p/locations/global/certificateMaps/m}.
     * A prior Certificate Manager certificate of this deployment is updated in place when GCP
     * allows it (same SANs); otherwise a new one is created and the prior one deleted after the
     * entries point at the new one.
     */
    public MapDeployment deployToProxyMap(String proxyCertificateMap,
                                          String certificateBaseName,
                                          String priorCertResourceName,
                                          CertificateBundle bundle,
                                          GoogleCredentials credentials) {
        Matcher map = MAP_NAME.matcher(proxyCertificateMap == null ? "" : proxyCertificateMap.trim());
        if (!map.find()) {
            throw new PermanentAgentException("DEPLOY_GCP_PROXY_FAILED",
                    "Unrecognised certificate map reference on the target proxy: " + proxyCertificateMap);
        }
        String projectId = map.group(1);
        String location = map.group(2);
        String mapId = map.group(3);

        String prior = GcpTargetProxyService.looksLikeCertManagerResourceName(priorCertResourceName)
                ? priorCertResourceName : null;
        String certResourceName;
        boolean created;
        if (prior != null && certificateManagerService.updateCertificate(prior, bundle, credentials)) {
            certResourceName = prior;
            created = false;
        } else {
            certResourceName = certificateManagerService.createCertificate(
                    projectId, location, GcpNameUtils.versionedId(certificateBaseName), bundle, credentials);
            created = true;
        }

        List<AppliedEntry> entries;
        try {
            entries = bindHostnames(projectId, location, mapId, certResourceName, bundle, credentials);
        } catch (RuntimeException e) {
            if (created) {
                // Certificate Manager refuses to delete a certificate an entry still uses.
                certificateManagerService.deleteCertificate(certResourceName, credentials);
            }
            throw e;
        }
        if (created && prior != null) {
            certificateManagerService.deleteCertificate(prior, credentials);
        }
        String mapName = "projects/" + projectId + "/locations/" + location + "/certificateMaps/" + mapId;
        log.info("Deployed through certificate map {}: certificate={}, entries={}",
                mapName, certResourceName, entries.size());
        return new MapDeployment(certResourceName, mapName, entries);
    }

    /**
     * Points the map entry of every DNS name on the leaf certificate (CN and SANs) at
     * {@code certResourceName}, creating entries that don't exist yet.
     */
    public List<AppliedEntry> bindHostnames(String projectId,
                                            String location,
                                            String mapId,
                                            String certResourceName,
                                            CertificateBundle bundle,
                                            GoogleCredentials credentials) {
        List<String> hostnames = CertificateIdentityUtils.extractAllHostnames(bundle.leafCertificate());
        if (hostnames.isEmpty()) {
            throw new PermanentAgentException("DEPLOY_CERT_INVALID",
                    "Could not extract any DNS hostnames (CN/SAN) from the leaf certificate");
        }
        Map<String, String> existingByHostname = certificateManagerService.listEntriesByHostname(
                projectId, location, mapId, credentials);

        List<AppliedEntry> applied = new ArrayList<>();
        for (String hostname : hostnames) {
            String entryFullName = existingByHostname.get(hostname.toLowerCase());
            if (entryFullName != null) {
                applied.add(new AppliedEntry(hostname, certificateManagerService.updateMapEntryCertificates(
                        entryFullName, certResourceName, credentials), "updated"));
            } else {
                String entryId = entryIdFor(hostname);
                applied.add(new AppliedEntry(hostname, certificateManagerService.createMapEntry(
                        projectId, location, mapId, entryId, hostname, certResourceName, credentials), "created"));
            }
        }
        return applied;
    }

    /** Entry IDs must be unique per map, and {@code *.example.com} must not collide with {@code example.com}. */
    static String entryIdFor(String hostname) {
        String name = hostname.startsWith("*.") ? "wildcard-" + hostname.substring(2) : hostname;
        return GcpNameUtils.toResourceId(name, "certping-entry");
    }
}
