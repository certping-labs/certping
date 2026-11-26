// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * CSS Modules are resolved by the bundler, not by jest. Echo the requested key
 * back so a component's class names stay legible in test output.
 */
const styleMock = new Proxy(
  {},
  {
    get: (_target, key) => (typeof key === "string" ? key : ""),
  },
);

export default styleMock;
