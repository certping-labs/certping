// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.exception.AuditExportRefusedException;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.async.CallableProcessingInterceptor;

import java.util.concurrent.Callable;

/**
 * Gives an audit export's slot back when its async request completes, whatever became of the body. A
 * {@code StreamingResponseBody} runs as a {@link Callable} ({@code StreamingResponseBodyReturnValueHandler} hands it
 * to {@code WebAsyncManager.startCallableProcessing}), so this callable interceptor sees every export: its
 * {@link #afterCompletion} runs after the body ended, after a timeout, after an error, and after the executor
 * rejected the body before it ran, the cases where the body's own release never happens. Releasing is idempotent
 * ({@link AuditTrailExporter.Permit}), so both may call it.
 *
 * <p>A request that times out before its export wrote anything ends as 503 {@code EXPORT_TIMEOUT}; once rows are
 * being written the status is sent and the export ends short ({@code X-Audit-Export-Rows} tells the client).
 * Requests that are not exports pass through untouched.
 */
public class AuditExportSlotInterceptor implements CallableProcessingInterceptor {

    @Override
    public <T> Object handleTimeout(NativeWebRequest request, Callable<T> task) {
        return permit(request) == null ? RESULT_NONE : AuditExportRefusedException.timedOut();
    }

    @Override
    public <T> void afterCompletion(NativeWebRequest request, Callable<T> task) {
        AuditTrailExporter.Permit permit = permit(request);
        if (permit != null) {
            permit.release();
        }
    }

    private static AuditTrailExporter.Permit permit(NativeWebRequest request) {
        Object held = request.getAttribute(AuditTrailExporter.PERMIT_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
        return held instanceof AuditTrailExporter.Permit permit ? permit : null;
    }
}
