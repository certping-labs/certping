// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditChange;
import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditEvents;
import com.certmanagement.audit.AuditReason;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditScope;
import com.certmanagement.audit.AuditSubject;
import com.certmanagement.iot.certificate.IotDeviceCertificate;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.profile.CertificateProfile;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Writes the machine-identity events of the audit trail: a device decommissioned, archived or restored; a device
 * source's sync started or its scheduled sync stopped; a device certificate's revocation requested; and a
 * certificate profile created, changed or deleted.
 *
 * <p>Each is written in the change's own transaction ({@link AuditRecorder#record}, which requires one): it
 * commits and rolls back with the change. The row written here is the action's one customer row (their history
 * lives in the IoT event tables, and the request interceptor's row is an internal {@code api.request} row).
 *
 * <p>A device is named by its name, a source by its display name and provider in words, a certificate by its
 * common name, a profile by its name; each is referenced by its xref. An operator's free-text note, a profile's
 * settings and a device's identifiers (serial number, hardware ids) are never part of a row.
 */
@Component
public class IotAuditRecorder {

    private static final Pattern CODE = Pattern.compile("^[A-Z][A-Z0-9_]{0,39}$");
    /** The system actor of the rows CertPing writes on what the SCEP agent reported. */
    public static final String SCEP_JOB = "scep";

    private static final Map<DeviceSourceProvider, String> PROVIDERS = Map.of(
            DeviceSourceProvider.INTUNE, "Microsoft Intune",
            DeviceSourceProvider.JAMF, "Jamf",
            DeviceSourceProvider.WORKSPACE_ONE, "Workspace ONE",
            DeviceSourceProvider.AWS_IOT, "AWS IoT",
            DeviceSourceProvider.AZURE_IOT, "Azure IoT",
            DeviceSourceProvider.GCP_IOT, "Google Cloud IoT",
            DeviceSourceProvider.CISCO, "Cisco",
            DeviceSourceProvider.LWM2M, "LwM2M");

    private final AuditRecorder recorder;

    public IotAuditRecorder(AuditRecorder recorder) {
        this.recorder = recorder;
    }

    // ── Devices ──────────────────────────────────────────────────────────

    /** {@code device} was decommissioned from {@code previousStatus}. */
    public void deviceDecommissioned(IotDevice device, Enum<?> previousStatus) {
        recorder.record(AuditEvents.success(AuditEventType.IOT_DEVICE_DECOMMISSIONED, device(device)
                .changes(List.of(new AuditChange("status", previousStatus == null ? null : previousStatus.name(),
                        device.getStatus() == null ? null : device.getStatus().name())))
                .build()));
    }

    public void deviceArchived(IotDevice device) {
        recorder.record(AuditEvents.success(AuditEventType.IOT_DEVICE_ARCHIVED, device(device).build()));
    }

    public void deviceRestored(IotDevice device) {
        recorder.record(AuditEvents.success(AuditEventType.IOT_DEVICE_RESTORED, device(device).build()));
    }

    // ── Device sources ───────────────────────────────────────────────────

    /** A member started the sync {@code syncXref} of {@code source}. */
    public void syncStarted(IotDeviceSource source, String syncXref) {
        Map<String, String> attributes = new LinkedHashMap<>();
        if (syncXref != null) {
            attributes.put("syncRef", syncXref);
        }
        recorder.record(AuditEvents.success(AuditEventType.IOT_SOURCE_SYNC_STARTED,
                source(source).attributes(attributes).build()));
    }

    /** A member stopped the scheduled sync of {@code source}. */
    public void syncStopped(IotDeviceSource source) {
        recorder.record(AuditEvents.success(AuditEventType.IOT_SOURCE_SYNC_STOPPED, source(source).build()));
    }

    /** The provider in words: "Microsoft Intune", "Jamf"; null for a manual source. */
    static String providerName(DeviceSourceProvider provider) {
        return provider == null ? null : PROVIDERS.get(provider);
    }

    // ── Certificates ─────────────────────────────────────────────────────

    /** A member asked for {@code certificate} to be revoked, for {@code reason}, as the operation {@code operationXref}. */
    public void certificateRevocationRequested(IotDeviceCertificate certificate, Enum<?> reason, String operationXref) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "reason", reason == null ? null : reason.name());
        put(attributes, "caProvider", certificate.getCaProvider() == null ? null
                : certificate.getCaProvider().trim().toUpperCase(java.util.Locale.ROOT));
        if (operationXref != null) {
            attributes.put("operationRef", operationXref);
        }
        recorder.record(AuditEvents.success(AuditEventType.IOT_CERTIFICATE_REVOKED, AuditSubject.builder()
                .organizationId(certificate.getOrganizationId())
                .resourceId(certificate.getId())
                .resourceRef(certificate.getCertificateXref())
                .name(certificate.getCommonName())
                .attributes(attributes)
                .build()));
    }

    /**
     * A device's enrollment ended without a certificate, as the agent reported it. {@code source} is null when no
     * device source is registered for the connection profile the agent named ({@code profileRef}). Isolated from the
     * caller's transaction: the trail never rolls back the enrollment's own record.
     */
    public void enrollmentFailed(Long organizationId, IotDeviceSource source, String profileRef, String enrollmentXref,
                                 String stage, boolean retryable, String errorCode) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "stage", stage);
        if (enrollmentXref != null) {
            attributes.put("enrollmentRef", enrollmentXref);
        }
        attributes.put("retryable", Boolean.toString(retryable));
        AuditSubject.AuditSubjectBuilder subject = source != null ? source(source)
                : AuditSubject.builder().organizationId(organizationId).name(profileRef);
        AuditReason reason = errorCode == null || errorCode.isBlank()
                ? AuditReason.of("ENROLLMENT_FAILED") : AuditReason.of(errorCode);
        try (AuditScope scope = AuditScope.system(SCEP_JOB, organizationId)) {
            recorder.recordIsolated(AuditEvents.failure(AuditEventType.IOT_ENROLLMENT_FAILED,
                    subject.attributes(attributes).build(), reason));
        }
    }

    // ── Certificate profiles ─────────────────────────────────────────────

    public void profileCreated(CertificateProfile profile, String sourceXref) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "lifecycleStatus", profile.getLifecycleStatus() == null ? null
                : profile.getLifecycleStatus().name());
        put(attributes, "targetPlatform", profile.getTargetPlatform());
        if (sourceXref != null) {
            attributes.put("sourceRef", sourceXref);
        }
        recorder.record(AuditEvents.success(AuditEventType.IOT_PROFILE_CREATED,
                profile(profile).attributes(attributes).build()));
    }

    /**
     * {@code profile} was changed: the settings named in {@code changedFields} (by name, never valued), its
     * lifecycle status from {@code statusBefore}, and whether the change was sent to the provider.
     */
    public void profileUpdated(CertificateProfile profile, Collection<String> changedFields, Enum<?> statusBefore,
                               boolean sentToProvider) {
        Map<String, String> attributes = new LinkedHashMap<>();
        List<String> names = changedFields == null ? List.of() : changedFields.stream()
                .filter(field -> field != null && field.matches("^[A-Za-z][A-Za-z0-9_.]{0,63}$"))
                .sorted()
                .toList();
        if (!names.isEmpty()) {
            attributes.put("changed", String.join(", ", names));
        }
        attributes.put("sentToProvider", Boolean.toString(sentToProvider));
        String before = statusBefore == null ? null : statusBefore.name();
        String after = profile.getLifecycleStatus() == null ? null : profile.getLifecycleStatus().name();
        List<AuditChange> changes = before != null && !before.equals(after)
                ? List.of(new AuditChange("lifecycleStatus", before, after)) : List.of();
        recorder.record(AuditEvents.success(AuditEventType.IOT_PROFILE_UPDATED,
                profile(profile).attributes(attributes).changes(changes).build()));
    }

    public void profileDeleted(CertificateProfile profile) {
        recorder.record(AuditEvents.success(AuditEventType.IOT_PROFILE_DELETED, profile(profile).build()));
    }

    private static AuditSubject.AuditSubjectBuilder device(IotDevice device) {
        return AuditSubject.builder()
                .organizationId(device.getOrganizationId())
                .resourceId(device.getId())
                .resourceRef(device.getDeviceXref())
                .name(device.getDeviceName());
    }

    private static AuditSubject.AuditSubjectBuilder source(IotDeviceSource source) {
        return AuditSubject.builder()
                .organizationId(source.getOrganizationId())
                .resourceId(source.getId())
                .resourceRef(source.getSourceXref())
                .name(source.getDisplayName())
                .provider(providerName(source.getProvider()));
    }

    private static AuditSubject.AuditSubjectBuilder profile(CertificateProfile profile) {
        return AuditSubject.builder()
                .organizationId(profile.getOrganizationId())
                .resourceId(profile.getId())
                .resourceRef(profile.getProfileXref())
                .name(profile.getName());
    }

    /** Kept only when code-shaped, so free text never becomes an attribute. */
    private static void put(Map<String, String> attributes, String name, String value) {
        if (value != null && CODE.matcher(value.trim()).matches()) {
            attributes.put(name, value.trim());
        }
    }
}
