// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import {
  ServerPagination,
  type ServerPaginationProps,
} from "@/components/ui/server-pagination";

const DEFAULT_PROPS: ServerPaginationProps = {
  page: 0,
  totalPages: 3,
  pageSize: 20,
  totalElements: 52,
  onPageChange: jest.fn(),
  onPageSizeChange: jest.fn(),
};

function renderPagination(overrides: Partial<ServerPaginationProps> = {}) {
  const props = {
    ...DEFAULT_PROPS,
    onPageChange: jest.fn(),
    onPageSizeChange: jest.fn(),
    ...overrides,
  };

  return {
    ...render(<ServerPagination {...props} />),
    props,
  };
}

describe("ServerPagination", () => {
  it("should render an empty range when there are zero elements", () => {
    renderPagination({ totalPages: 0, totalElements: 0 });

    expect(screen.getByText("Showing 0 to 0 of 0 entries")).toBeInTheDocument();
    expect(screen.getByText("Page 1 of 1")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Go to first page" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Go to previous page" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Go to next page" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Go to last page" }),
    ).toBeDisabled();
  });

  it("should format an exact total", () => {
    renderPagination({
      page: 600,
      pageSize: 20,
      totalPages: 618,
      totalElements: 12_345,
    });

    expect(
      screen.getByText("Showing 12,001 to 12,020 of 12,345 entries"),
    ).toBeInTheDocument();
    expect(screen.getByText("Page 601 of 618")).toBeInTheDocument();
  });

  it("should show a capped total as a lower bound", () => {
    renderPagination({
      page: 3,
      pageSize: 25,
      totalPages: 400,
      totalElements: 10_000,
      totalCapped: true,
    });

    expect(
      screen.getByText("Showing 76 to 100 of 10,000+ entries"),
    ).toBeInTheDocument();
    expect(screen.getByText("Page 4 of 400+")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Go to next page" }),
    ).toBeEnabled();
  });

  it("should disable only the navigation buttons beyond each boundary", () => {
    const { rerender } = renderPagination();

    expect(
      screen.getByRole("button", { name: "Go to first page" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Go to previous page" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Go to next page" }),
    ).toBeEnabled();
    expect(
      screen.getByRole("button", { name: "Go to last page" }),
    ).toBeEnabled();

    rerender(<ServerPagination {...DEFAULT_PROPS} page={2} />);

    expect(
      screen.getByRole("button", { name: "Go to first page" }),
    ).toBeEnabled();
    expect(
      screen.getByRole("button", { name: "Go to previous page" }),
    ).toBeEnabled();
    expect(
      screen.getByRole("button", { name: "Go to next page" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Go to last page" }),
    ).toBeDisabled();
  });

  it("should disable every interactive control while a request is pending", () => {
    renderPagination({ page: 1, disabled: true });

    expect(
      screen.getByRole("combobox", { name: "Rows per page" }),
    ).toBeDisabled();
    expect(screen.getByRole("combobox", { name: "Go to page" })).toBeDisabled();
    for (const navigationButton of screen.getAllByRole("button")) {
      expect(navigationButton).toBeDisabled();
    }
  });

  it("should limit large page lists while retaining nearby boundaries", async () => {
    const user = userEvent.setup();
    renderPagination({ page: 20, totalPages: 40 });

    await user.click(screen.getByRole("combobox", { name: "Go to page" }));

    expect(
      await screen.findByRole("option", { name: "1" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "21" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "40" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "2" })).not.toBeInTheDocument();
  });

  it("should emit zero-based page changes from navigation controls", async () => {
    const user = userEvent.setup();
    const { props } = renderPagination({ page: 1, totalPages: 4 });

    await user.click(screen.getByRole("button", { name: "Go to first page" }));
    await user.click(
      screen.getByRole("button", { name: "Go to previous page" }),
    );
    await user.click(screen.getByRole("button", { name: "Go to next page" }));
    await user.click(screen.getByRole("button", { name: "Go to last page" }));
    await user.click(screen.getByRole("combobox", { name: "Go to page" }));
    await user.click(await screen.findByRole("option", { name: "4" }));

    expect(props.onPageChange).toHaveBeenNthCalledWith(1, 0);
    expect(props.onPageChange).toHaveBeenNthCalledWith(2, 0);
    expect(props.onPageChange).toHaveBeenNthCalledWith(3, 2);
    expect(props.onPageChange).toHaveBeenNthCalledWith(4, 3);
    expect(props.onPageChange).toHaveBeenNthCalledWith(5, 3);
  });

  it("should emit a supported page size up to 200", async () => {
    const user = userEvent.setup();
    const { props } = renderPagination();

    await user.click(screen.getByRole("combobox", { name: "Rows per page" }));
    await user.click(await screen.findByRole("option", { name: "200" }));

    expect(props.onPageSizeChange).toHaveBeenCalledTimes(1);
    expect(props.onPageSizeChange).toHaveBeenCalledWith(200);
  });

  it("should restrict page sizes when an endpoint supplies its own limits", async () => {
    const user = userEvent.setup();
    renderPagination({ pageSizeOptions: [10, 20, 50, 100] });

    await user.click(screen.getByRole("combobox", { name: "Rows per page" }));

    expect(
      await screen.findByRole("option", { name: "100" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("option", { name: "200" }),
    ).not.toBeInTheDocument();
  });
});
