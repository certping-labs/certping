// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cbom;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.cyclonedx.Version;
import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Iterator;
import java.util.Map;

/**
 * Writes a CycloneDX 1.6 JSON document whose {@code components} array is produced one
 * {@link Component} at a time through the library's own version-aware mapper, so the output
 * matches {@link BomJsonGenerator#toJsonString()} without holding every component in memory.
 * The document is only well-formed once {@link #finish()} has run: a failure part-way through
 * leaves the output visibly truncated instead of a valid document with missing components.
 */
final class CycloneDxJsonWriter extends BomJsonGenerator implements AutoCloseable {

    private static final String COMPONENTS = "components";

    private final JsonGenerator generator;
    private final ObjectWriter componentWriter;

    CycloneDxJsonWriter(Bom envelope, OutputStream out) throws IOException {
        super(envelope, Version.VERSION_16);
        JsonNode head = toJsonNode();
        // cyclonedx-core-java still uses Jackson 2, so this writer stays on its mapper and types.
        generator = mapper.getFactory().createGenerator(out)
                .useDefaultPrettyPrinter()
                .disable(JsonGenerator.Feature.AUTO_CLOSE_JSON_CONTENT);
        componentWriter = mapper.writerFor(Component.class).without(SerializationFeature.FLUSH_AFTER_WRITE_VALUE);

        generator.writeStartObject();
        for (Iterator<Map.Entry<String, JsonNode>> fields = head.properties().iterator(); fields.hasNext(); ) {
            Map.Entry<String, JsonNode> field = fields.next();
            if (!COMPONENTS.equals(field.getKey())) {
                generator.writeFieldName(field.getKey());
                generator.writeTree(field.getValue());
            }
        }
        generator.writeArrayFieldStart(COMPONENTS);
    }

    void write(Component component) throws IOException {
        componentWriter.writeValue(generator, component);
    }

    void finish() throws IOException {
        generator.writeEndArray();
        generator.writeEndObject();
    }

    @Override
    public void close() throws IOException {
        generator.close();
    }
}
