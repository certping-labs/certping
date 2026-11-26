// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.DeploymentResult;
import com.certping.agent.model.message.CertDeploymentMessage;

/**
 * Common contract for deployment targets.
 */
public interface DeploymentAdapter {

    /**
     * Deploys the parsed certificate bundle to a target and returns the identifier of the resulting resource.
     */
    DeploymentResult deploy(CertificateBundle bundle, CertDeploymentMessage message);
}
