// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.acme;

import com.certping.agent.model.message.CertManualTxtResponse;

import java.net.URL;
import java.util.List;

/** Result of {@code requestTxtRecords}: DNS-01 TXT rows, ACME order URL, account URL, KV URI of the ACME account key. */
public record ManualTxtResult(
        List<CertManualTxtResponse.TxtRecord> txtRecords,
        URL orderUrl,
        URL accountUrl,
        String acmeAccountHandle
) {}
