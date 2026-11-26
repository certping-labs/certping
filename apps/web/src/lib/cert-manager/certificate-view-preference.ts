// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { ViewMode } from "@/components/ui/view-switcher";

const CERTIFICATE_VIEW_KEY = "certificates-view-preference";

export function readCertificateViewPreference(
  storage: Pick<Storage, "getItem">,
): ViewMode | null {
  const storedValue = storage.getItem(CERTIFICATE_VIEW_KEY);
  if (storedValue === "table" || storedValue === "card") {
    return storedValue;
  }
  return null;
}

export function writeCertificateViewPreference(
  storage: Pick<Storage, "setItem">,
  viewMode: ViewMode,
): void {
  storage.setItem(CERTIFICATE_VIEW_KEY, viewMode);
}
