// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.organization;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class OrganizationDtoValidationTest {

    private static final Validator VALIDATOR = Validation.buildDefaultValidatorFactory().getValidator();

    @ParameterizedTest
    @ValueSource(ints = {-1, 0, 61, 100_000})
    void refusesAHeartbeatCadenceOutsideOneToSixty(int minutes) {
        assertThat(cadenceViolations(minutes)).isNotEmpty();
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 5, 60})
    void acceptsAHeartbeatCadenceFromOneToSixty(int minutes) {
        assertThat(cadenceViolations(minutes)).isEmpty();
    }

    private static Set<ConstraintViolation<OrganizationDto>> cadenceViolations(int minutes) {
        OrganizationDto dto = OrganizationDto.builder().name("Acme").agentHeartbeatCadenceMinutes(minutes).build();
        return VALIDATOR.validateProperty(dto, "agentHeartbeatCadenceMinutes");
    }
}
