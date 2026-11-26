// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { ThemeToggle } from "@/components/theme-toggle";

const setTheme = jest.fn();
let resolvedTheme = "light";

jest.mock("next-themes", () => ({
  useTheme: () => ({ resolvedTheme, setTheme }),
}));

describe("ThemeToggle", () => {
  beforeEach(() => {
    setTheme.mockReset();
    resolvedTheme = "light";
    document.documentElement.className = "";
  });

  it("switches to dark on the first click when the rendered page is light", async () => {
    const user = userEvent.setup();
    render(<ThemeToggle />);

    await user.click(
      screen.getByRole("button", { name: "Switch to dark theme" }),
    );

    expect(setTheme).toHaveBeenCalledWith("dark");
  });

  it("switches to light on the first click when the rendered page is dark", async () => {
    resolvedTheme = "dark";
    const user = userEvent.setup();
    render(<ThemeToggle />);

    await user.click(
      screen.getByRole("button", { name: "Switch to light theme" }),
    );

    expect(setTheme).toHaveBeenCalledWith("light");
  });

  it("updates immediately so consecutive clicks switch both directions", async () => {
    const user = userEvent.setup();
    render(<ThemeToggle />);
    const toggle = screen.getByRole("button", {
      name: "Switch to dark theme",
    });

    await user.click(toggle);
    await user.click(toggle);

    expect(setTheme).toHaveBeenNthCalledWith(1, "dark");
    expect(setTheme).toHaveBeenNthCalledWith(2, "light");
  });
});
