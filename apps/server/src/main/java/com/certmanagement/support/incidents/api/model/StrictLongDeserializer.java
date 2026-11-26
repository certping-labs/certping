// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.api.model;

import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.exc.InvalidFormatException;
import tools.jackson.databind.ValueDeserializer;

final class StrictLongDeserializer extends ValueDeserializer<Long> {

    @Override
    public Long deserialize(JsonParser parser, DeserializationContext context) {
        JsonToken token = parser.currentToken();
        if (token == JsonToken.VALUE_NUMBER_INT) {
            return parser.getLongValue();
        }
        if (token == JsonToken.VALUE_NULL) {
            return null;
        }
        throw InvalidFormatException.from(parser, "Expected a JSON number", parser.getString(), Long.class);
    }
}
