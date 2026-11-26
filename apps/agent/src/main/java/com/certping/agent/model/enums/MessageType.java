// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.enums;

import com.certping.agent.exception.PermanentAgentException;

public enum MessageType {
    CERT_ISSUANCE,
    CERT_RENEWAL,
    CERT_DEPLOYMENT,
    CERT_MANUAL_TXT_REQUEST,
    CERT_MANUAL_DNS_VALIDATE,
    CERT_ISSUANCE_RESPONSE,
    CERT_DEPLOYMENT_RESPONSE,
    CERT_MANUAL_TXT_RESPONSE,
    CERT_REVOCATION_COMMAND,
    /**
     * The server requests removal of a stored cert secret in the agent Key Vault (e.g. after marking EXPIRED).
     */
    CERT_OWN_SECRET_DELETE,
    CERT_REVOCATION_RESPONSE,
    CERT_SECRET_DELETE_COMMAND,
    CERT_SECRET_DELETE_RESPONSE,
    AGENT_HEALTH_HEARTBEAT,
    AGENT_HEARTBEAT_CADENCE_UPDATE,
    AGENT_DEEP_HEALTH_CHECK,
    AGENT_DEEP_HEALTH_CHECK_RESPONSE,
    /** Outbound: per-CA connectivity and configuration health. Provider-neutral payload. */
    AGENT_CA_HEALTH_REPORT,
    /** Outbound: a SCEP enrollment was received and parsed, before Intune validation. Audit only. */
    SCEP_CERT_REQUESTED,
    /** Outbound: a device certificate was issued over SCEP. Metadata only, no key material. */
    SCEP_CERT_ISSUED,
    /** Outbound: a SCEP enrollment ended REJECTED (Intune) or FAILED (CA) with no certificate. */
    SCEP_CERT_RESULT,
    AGENT_ERROR,
    CERT_DISCOVERY,
    CERT_DISCOVERY_RESPONSE,
    CERT_DISCOVERY_COMPLETE,

    /** The server asks the agent to pull device identities from the org's MDM (Intune). */
    DEVICE_IDENTITY_SYNC_COMMAND,
    /** One page of devices on the way back. Chunked like discovery. */
    DEVICE_IDENTITY_SYNC_RESPONSE_PART,
    /** Terminal message for a sync run; a FULL run triggers orphan detection in the server. */
    DEVICE_IDENTITY_SYNC_RESPONSE_COMPLETE,
    /** Agent-owned health observation for one endpoint-management or IoT source. */
    IOT_DEVICE_SOURCE_HEALTH,
    IOT_CERTIFICATE_PROFILE_COMMAND,
    IOT_CERTIFICATE_PROFILE_RESPONSE,
    IOT_CERTIFICATE_PROFILE_SYNC_COMMAND,
    IOT_CERTIFICATE_PROFILE_SYNC_RESPONSE_PART,
    IOT_CERTIFICATE_PROFILE_SYNC_RESPONSE_COMPLETE,
    /** Inbound: best-effort renewal nudge — force one managed device to check in with Intune. */
    IOT_DEVICE_SYNC_COMMAND,
    /** Outbound: the outcome of a device-sync nudge (accepted / rejected / unavailable / skipped). */
    IOT_DEVICE_SYNC_RESPONSE,
    IOT_CERTIFICATE_REVOCATION_COMMAND,
    IOT_CERTIFICATE_REVOCATION_RESULT,
    IOT_INTUNE_REVOCATION_POLL_COMMAND,
    IOT_INTUNE_REVOCATION_POLL_RESULT,
    IOT_INTUNE_REVOCATION_UPLOAD_COMMAND,
    IOT_INTUNE_REVOCATION_UPLOAD_RESULT;

    public static MessageType fromString(String value) {
        try {
            return MessageType.valueOf(value);
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new PermanentAgentException("UNKNOWN_MESSAGE_TYPE", "Unknown MessageType: " + value);
        }
    }
}
