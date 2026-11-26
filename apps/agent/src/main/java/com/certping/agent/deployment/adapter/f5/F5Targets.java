// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.f5;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Parsed shape of {@code targetsJson} for {@code F5_BIGIP}.
 *
 * @param certBaseName  optional — base name for F5 SSL objects ({@code {base}_v{n}}).
 *                      Targets-first precedence: when set, always wins. Changing it triggers
 *                      a rename — the next deploy starts a fresh {@code _v1} family under the
 *                      new base; old {@code _v{n}} cert/key objects on the BIG-IP become
 *                      orphan (operator cleans up manually). When blank, falls back to
 *                      stripping {@code _v\d+$} from the prior {@code result.certName} (renewal
 *                      stability), then auto-derives from cert xref / domain.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record F5Targets(String certBaseName) {}
