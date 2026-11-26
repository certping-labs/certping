// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { setupServer } from "msw/node";
import { mswHandlers } from "@/test/msw/handlers";

export const server = setupServer(...mswHandlers);
