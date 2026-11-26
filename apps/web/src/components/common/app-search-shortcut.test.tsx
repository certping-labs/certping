// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { renderToString } from "react-dom/server";

import { AppSearchShortcut } from "@/components/common/app-search-shortcut";

describe("AppSearchShortcut", () => {
  it("uses the non-platform-specific shortcut during server rendering", () => {
    const markup = renderToString(<AppSearchShortcut />);

    expect(markup).toContain("Ctrl");
    expect(markup).not.toContain("⌘");
  });

  it("is decorative, so it cannot leak into its button's accessible name", () => {
    // It sits inside the search trigger. Labelling it made a screen reader
    // announce that control as "Search ⌘ + K shortcut".
    const markup = renderToString(<AppSearchShortcut />);

    expect(markup).toContain('aria-hidden="true"');
    expect(markup).not.toContain("aria-label");
  });
});
