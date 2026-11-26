// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.entity;

import com.certmanagement.iot.enums.ThingFormFactor;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.OffsetDateTime;

/**
 * Cloud IoT registry facet — AWS IoT, Azure IoT.
 *
 * <p>Shares its primary key with {@code iot_device}: a device has a row here only if it came
 * from a registry that reports these attributes. MDM-sourced endpoints get an
 * {@link IotDeviceEndpointPosture} row instead, and neither is a superset of the other — a
 * thing has no compliance state, an endpoint has no attestation type.
 */
@Entity
@Table(name = "iot_device_connected_thing")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IotDeviceConnectedThing {

    @Id
    @Column(name = "device_id")
    private Long deviceId;

    /** X509 | TPM | SYMMETRIC_KEY — how the device proves who it is at registration. */
    @Column(name = "attestation_type", length = 30)
    private String attestationType;

    /** IoT Hub name, or AWS account + region. */
    @Column(name = "hub_or_account_ref", length = 255)
    private String hubOrAccountRef;

    @Column(name = "thing_type", length = 200)
    private String thingType;

    @Enumerated(EnumType.STRING)
    @Column(name = "form_factor", length = 20)
    private ThingFormFactor formFactor;

    @Column(name = "connectivity_state", length = 50)
    private String connectivityState;

    @Column(name = "last_connected_at")
    private OffsetDateTime lastConnectedAt;

    /** Thing attributes / device twin tags, as the registry reported them. */
    @Column(name = "custom_attributes", columnDefinition = "jsonb")
    private String customAttributes;
}
