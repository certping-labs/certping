// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, waitFor } from "@testing-library/react";

import { MorphText } from "@/components/ui/morph-text";

const controller = {
  attach: jest.fn(),
  update: jest.fn(),
  destroy: jest.fn(),
};

jest.mock("torph", () => ({
  MorphController: jest.fn(() => controller),
}));

describe("MorphText", () => {
  afterEach(() => {
    delete (HTMLElement.prototype as Partial<HTMLElement>).animate;
  });

  it("swaps the text in place where the browser cannot animate", () => {
    const { rerender } = render(<MorphText>Copy</MorphText>);
    rerender(<MorphText>Copied</MorphText>);

    expect(screen.getByText("Copied")).toBeInTheDocument();
    expect(controller.attach).not.toHaveBeenCalled();
  });

  it("attaches torph on the first change, seeds the old text, then morphs", async () => {
    HTMLElement.prototype.animate = jest.fn();
    const { rerender, unmount } = render(<MorphText>Save</MorphText>);
    const span = screen.getByText("Save");

    expect(controller.attach).not.toHaveBeenCalled();

    rerender(<MorphText>Saving…</MorphText>);
    await waitFor(() => expect(controller.attach).toHaveBeenCalledTimes(1));

    expect(controller.attach).toHaveBeenCalledWith(span, expect.any(Object));
    expect(controller.update.mock.calls).toEqual([["Save"], ["Saving…"]]);

    rerender(<MorphText>Save</MorphText>);

    expect(controller.attach).toHaveBeenCalledTimes(1);
    expect(controller.update).toHaveBeenLastCalledWith("Save");

    unmount();

    expect(controller.destroy).toHaveBeenCalledTimes(1);
    expect(span.textContent).toBe("Save");
  });
});
