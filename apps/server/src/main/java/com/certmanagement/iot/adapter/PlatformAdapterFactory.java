// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.adapter;

import com.certmanagement.iot.enums.DeviceSourceProvider;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Resolves the {@link PlatformAdapter} for a platform type.
 *
 * <p>Implementations are discovered as Spring beans, so a new connector is one {@code @Component}
 * and no change here.
 *
 * <p>Registration also answers "can CertPing sync this platform?". A row may exist for a type
 * nobody has written an adapter for. {@link #isSupported} keeps reserved providers out of the
 * sync path until both the agent connector and the server's mapper exist.
 */
@Component
public class PlatformAdapterFactory {

    private final Map<DeviceSourceProvider, PlatformAdapter> adapters;

    public PlatformAdapterFactory(List<PlatformAdapter> adapterList) {
        this.adapters = adapterList.stream()
                .collect(Collectors.toMap(PlatformAdapter::getProvider, Function.identity()));
    }

    /** The adapter for this platform, or a 400 naming what is actually wired. */
    public PlatformAdapter getAdapter(DeviceSourceProvider provider) {
        return find(provider).orElseThrow(() -> new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "No connector for provider " + provider + ". Supported: " + supported()));
    }

    public Optional<PlatformAdapter> find(DeviceSourceProvider provider) {
        return Optional.ofNullable(adapters.get(provider));
    }

    public boolean isSupported(DeviceSourceProvider provider) {
        return provider != null && adapters.containsKey(provider);
    }

    /** Wired platforms, ordered for stable error messages and logs. */
    public List<DeviceSourceProvider> supported() {
        return adapters.keySet().stream().sorted().toList();
    }
}
