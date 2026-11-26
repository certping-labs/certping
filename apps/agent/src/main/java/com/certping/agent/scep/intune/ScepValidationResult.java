// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep.intune;

/**
 * Outcome of SCEP challenge validation, carrying the device identifier with explicit provenance.
 *
 * <p>Microsoft's {@code ValidateRequest} reports pass/fail only, so provenance has to be argued
 * per field. A tamper test against a live tenant settled it for the CSR subject: resubmitting a
 * request whose subject had been altered was rejected with {@code SubjectNameMismatch}, proving
 * Intune binds the subject to the challenge it issued. The challenge token's {@code <DeviceId>}
 * element is <em>not</em> covered — it sits outside the signed {@code <Data>} block — so it earns
 * {@link Assurance#MICROSOFT_VALIDATED} only when a real Microsoft call accepted the request and
 * the DeviceId equals that validated subject. Any identifier not proven by that Microsoft call
 * stays {@link Assurance#ASSERTED}. The server only auto-links devices from
 * {@code MICROSOFT_VALIDATED} identifiers; an asserted one is stored for investigation only.
 */
public record ScepValidationResult(DeviceIdentifier identifier) {

    private static final int MAX_IDENTIFIER_LENGTH = 500;

    public enum IdentifierType { MANAGED_DEVICE_ID, ENTRA_DEVICE_ID, ENTRA_OBJECT_ID, UNKNOWN }

    public enum Assurance { MICROSOFT_VALIDATED, ASSERTED, ABSENT }

    /** Bounded identifier facts. {@code value} is null exactly when {@code assurance} is ABSENT. */
    public record DeviceIdentifier(String value, IdentifierType type, Assurance assurance, String provider) {
    }

    private static final DeviceIdentifier NO_IDENTIFIER =
            new DeviceIdentifier(null, IdentifierType.UNKNOWN, Assurance.ABSENT, "INTUNE");

    public ScepValidationResult {
        identifier = identifier == null ? NO_IDENTIFIER : identifier;
    }

    /** Validation passed but revealed no device identifier. */
    public static ScepValidationResult absent() {
        return new ScepValidationResult(NO_IDENTIFIER);
    }

    /** An identifier visible in the request but not proven to be covered by Microsoft validation. */
    public static ScepValidationResult asserted(String value, IdentifierType type) {
        return new ScepValidationResult(identifier(value, type, Assurance.ASSERTED));
    }

    /**
     * For an identifier carried by a challenge that a real Microsoft {@code ValidateRequest} call
     * accepted. Never call this from a validator that did not contact Microsoft.
     */
    public static ScepValidationResult microsoftValidated(String value, IdentifierType type) {
        return new ScepValidationResult(identifier(value, type, Assurance.MICROSOFT_VALIDATED));
    }

    public boolean hasIdentifier() {
        return identifier.assurance() != Assurance.ABSENT;
    }

    private static DeviceIdentifier identifier(String value, IdentifierType type, Assurance assurance) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("identifier value must not be blank");
        }
        String trimmed = value.trim();
        if (trimmed.length() > MAX_IDENTIFIER_LENGTH) {
            throw new IllegalArgumentException("identifier value exceeds " + MAX_IDENTIFIER_LENGTH + " characters");
        }
        return new DeviceIdentifier(trimmed, type == null ? IdentifierType.UNKNOWN : type, assurance, "INTUNE");
    }
}
