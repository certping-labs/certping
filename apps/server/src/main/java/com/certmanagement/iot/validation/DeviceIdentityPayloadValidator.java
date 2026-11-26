// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.validation;

import com.certmanagement.iot.dto.request.ConnectedThingAttributes;
import com.certmanagement.iot.dto.request.DeviceIdentityPayload;
import org.springframework.stereotype.Component;

import java.util.List;

/** Validates provider payloads against the device registry's persistence limits. */
@Component
public class DeviceIdentityPayloadValidator {

    public String validate(DeviceIdentityPayload payload) {
        if (payload == null) {
            return "device payload is required";
        }
        List<BoundedValue> deviceValues = List.of(
                value("externalId", payload.externalId(), 500),
                value("serialNumber", payload.serialNumber(), 255),
                value("deviceName", payload.deviceName(), 255),
                value("manufacturer", payload.manufacturer(), 200),
                value("model", payload.model(), 200),
                value("operatingSystem", payload.operatingSystem(), 50),
                value("osVersion", payload.osVersion(), 100),
                value("complianceState", payload.complianceState(), 100),
                value("managementAgent", payload.managementAgent(), 50),
                value("enrollmentType", payload.enrollmentType(), 100),
                value("jailbrokenState", payload.jailbrokenState(), 20));
        String error = firstError(deviceValues);
        return error != null ? error : validateConnectedThing(payload.connectedThing());
    }

    private static String validateConnectedThing(ConnectedThingAttributes connectedThing) {
        if (connectedThing == null) {
            return null;
        }
        return firstError(List.of(
                value("connectedThing.attestationType", connectedThing.attestationType(), 30),
                value("connectedThing.hubOrAccountRef", connectedThing.hubOrAccountRef(), 255),
                value("connectedThing.thingType", connectedThing.thingType(), 200),
                value("connectedThing.formFactor", connectedThing.formFactor(), 20),
                value("connectedThing.connectivityState", connectedThing.connectivityState(), 50)));
    }

    private static String firstError(List<BoundedValue> values) {
        return values.stream()
                .filter(value -> value.content() != null
                        && value.content().trim().length() > value.maximumLength())
                .map(value -> value.field() + " exceeds " + value.maximumLength() + " characters")
                .findFirst().orElse(null);
    }

    private static BoundedValue value(String field, String content, int maximumLength) {
        return new BoundedValue(field, content, maximumLength);
    }

    private record BoundedValue(String field, String content, int maximumLength) {
    }
}
