// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { AxiosError } from "axios";

export const isAccessDeniedError = (error: unknown): boolean => {
  if (!(error instanceof AxiosError)) {
    return false;
  }

  const status = error.response?.status;
  return status === 401 || status === 403;
};

export const isNotFoundError = (error: unknown): boolean => {
  if (!(error instanceof AxiosError)) {
    return false;
  }

  return error.response?.status === 404;
};

export const isConflictError = (error: unknown): boolean => {
  if (!(error instanceof AxiosError)) {
    return false;
  }

  return error.response?.status === 409;
};

export const isTransientRequestError = (error: unknown): boolean => {
  if (!(error instanceof AxiosError)) {
    return true;
  }

  const status = error.response?.status;
  return (
    status === undefined ||
    status === 408 ||
    status === 425 ||
    status === 429 ||
    status >= 500
  );
};

export const isUnprocessableError = (error: unknown): boolean =>
  error instanceof AxiosError && error.response?.status === 422;
