// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment;

/**
 * Successful deployment result returned by an adapter.
 *
 * <p>{@code targetResourceId} identifies the remote object that now holds the certificate.
 * {@code configJson} is optional adapter state for the server to persist after the first deployment.
 */
public record DeploymentResult(String targetResourceId, String configJson) {

    public static DeploymentResult of(String targetResourceId) {
        return new DeploymentResult(targetResourceId, null);
    }

    public static DeploymentResult of(String targetResourceId, String configJson) {
        return new DeploymentResult(targetResourceId, configJson);
    }
}
