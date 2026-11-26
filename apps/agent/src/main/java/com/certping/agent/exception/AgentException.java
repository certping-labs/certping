// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.exception;

import lombok.Getter;

@Getter
public abstract class AgentException extends RuntimeException {

    private final String errorCode;

    protected AgentException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    protected AgentException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }
}
