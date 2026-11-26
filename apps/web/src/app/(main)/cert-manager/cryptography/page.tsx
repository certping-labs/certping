// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { CbomPqcDashboard } from "@/components/cert-manager/cbom-pqc-dashboard";

/** PQC_READINESS is enforced by `FeatureRouteGate` (see feature-routes). */
export default function CryptographyPage() {
  return <CbomPqcDashboard />;
}
