// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

record NamecheapQueryParam(String name, String value) {

    static String buildQuery(List<NamecheapQueryParam> params) {
        List<String> encoded = new ArrayList<>();
        for (NamecheapQueryParam param : params) {
            encoded.add(encode(param.name()) + "=" + encode(param.value()));
        }
        return String.join("&", encoded);
    }

    static void addOptional(List<NamecheapQueryParam> params, String name, String value) {
        if (value != null && !value.isBlank()) {
            params.add(new NamecheapQueryParam(name, value));
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
