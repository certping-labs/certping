// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.config;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import org.springframework.boot.jackson.autoconfigure.JsonMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.cfg.CoercionAction;
import tools.jackson.databind.cfg.CoercionInputShape;
import tools.jackson.databind.type.LogicalType;

/**
 * Numbers and booleans must arrive as JSON numbers and booleans: a quoted "123" or "true" is
 * rejected rather than silently coerced, so a client bug surfaces as a 400 instead of bad data.
 */
@Configuration(proxyBeanMethods = false)
class JacksonConfig {

    @Bean
    JsonMapperBuilderCustomizer strictScalarCoercionCustomizer() {
        return builder -> builder
                .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS)
                .withCoercionConfig(LogicalType.Integer,
                        cfg -> cfg.setCoercion(CoercionInputShape.String, CoercionAction.Fail))
                .withCoercionConfig(LogicalType.Float,
                        cfg -> cfg.setCoercion(CoercionInputShape.String, CoercionAction.Fail))
                .withCoercionConfig(LogicalType.Boolean,
                        cfg -> cfg.setCoercion(CoercionInputShape.String, CoercionAction.Fail));
    }

    /**
     * Jackson 3 only auto-detects public constructors as creators; Jackson 2 accepted any. Classes
     * with a package-private all-arguments constructor and no no-arguments one (Lombok builders,
     * records in nested classes) keep deserializing as before.
     */
    @Bean
    JsonMapperBuilderCustomizer creatorVisibilityCustomizer() {
        return builder -> builder.changeDefaultVisibility(
                visibility -> visibility.withCreatorVisibility(JsonAutoDetect.Visibility.ANY));
    }
}
