// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

final class NamecheapDnsXml {

    private NamecheapDnsXml() {}

    static Document parse(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setExpandEntityReferences(false);
        factory.setNamespaceAware(false);
        return factory.newDocumentBuilder()
                .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    static void verifyGetHostsSuccess(Document doc, String errorPrefix) {
        verifyApiStatusOk(doc, errorPrefix);
        Element result = firstElement(doc, "DomainDNSGetHostsResult");
        if (result != null && "false".equalsIgnoreCase(result.getAttribute("IsUsingOurDNS"))) {
            throw new PermanentAgentException("DNS_ZONE_NOT_FOUND",
                    errorPrefix + ": domain is not using Namecheap DNS");
        }
    }

    static void verifySetHostsSuccess(Document doc, String errorPrefix) {
        verifyApiStatusOk(doc, errorPrefix);
        Element result = firstElement(doc, "DomainDNSSetHostsResult");
        if (result != null && "false".equalsIgnoreCase(result.getAttribute("IsSuccess"))) {
            throw new TransientAgentException("DNS_PROVIDER_ERROR",
                    errorPrefix + ": setHosts returned IsSuccess=false");
        }
    }

    private static void verifyApiStatusOk(Document doc, String errorPrefix) {
        Element response = doc.getDocumentElement();
        if ("OK".equalsIgnoreCase(response.getAttribute("Status"))) {
            return;
        }
        String message = extractErrorMessage(response);
        if (message.contains("101710") || message.contains("101715") || message.contains("101610")) {
            throw new PermanentAgentException("DNS_AUTH_FAILED", errorPrefix + ": " + message);
        }
        if (message.toLowerCase().contains("domain not found")) {
            throw new PermanentAgentException("DNS_ZONE_NOT_FOUND", errorPrefix + ": " + message);
        }
        if (isRateLimited(message)) {
            throw new RetryableAgentException("DNS_PROVIDER_THROTTLED",
                    errorPrefix + ": Namecheap rate limited: " + message);
        }
        throw new TransientAgentException("DNS_PROVIDER_ERROR", errorPrefix + ": " + message);
    }

    static List<NamecheapDnsRecord> hostRecords(Document doc) {
        NodeList nodes = doc.getElementsByTagName("host");
        if (nodes.getLength() == 0) {
            nodes = doc.getElementsByTagName("Host");
        }

        List<NamecheapDnsRecord> records = new ArrayList<>();
        for (int i = 0; i < nodes.getLength(); i++) {
            Element host = (Element) nodes.item(i);
            records.add(new NamecheapDnsRecord(
                    host.getAttribute("Name"),
                    host.getAttribute("Type"),
                    host.getAttribute("Address"),
                    emptyToNull(host.getAttribute("MXPref")),
                    emptyToNull(host.getAttribute("TTL")),
                    emptyToNull(host.getAttribute("Flag")),
                    emptyToNull(host.getAttribute("Tag"))));
        }
        return records;
    }

    private static String extractErrorMessage(Element response) {
        NodeList errors = response.getElementsByTagName("Error");
        if (errors.getLength() == 0) {
            return "Status=" + response.getAttribute("Status");
        }
        Element error = (Element) errors.item(0);
        return error.getAttribute("Number") + " " + error.getTextContent();
    }

    private static Element firstElement(Document doc, String tagName) {
        NodeList nodes = doc.getElementsByTagName(tagName);
        return nodes.getLength() == 0 ? null : (Element) nodes.item(0);
    }

    private static String emptyToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private static boolean isRateLimited(String message) {
        String normalized = message.toLowerCase();
        return normalized.contains("too many requests")
                || normalized.contains("rate limit")
                || normalized.contains("rate-limit")
                || normalized.contains("throttle");
    }
}
