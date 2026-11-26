// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import GlobalError from "@/app/error";

jest.mock("@/lib/logger/logger.service", () => ({
  logger: {
    error: jest.fn(),
  },
}));

describe("GlobalError", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
  });

  it("renders digest when present", () => {
    render(
      <GlobalError
        error={
          { name: "Error", message: "Boom", digest: "abc" } as Error & {
            digest?: string;
          }
        }
        reset={() => {}}
      />,
    );
    expect(screen.getByText(/Error ID:/)).toBeInTheDocument();
    expect(screen.getByText(/abc/)).toBeInTheDocument();
  });

  it("does not render digest when missing", () => {
    render(
      <GlobalError
        error={
          { name: "Error", message: "Boom" } as Error & { digest?: string }
        }
        reset={() => {}}
      />,
    );
    expect(screen.queryByText(/Error ID:/)).not.toBeInTheDocument();
  });

  it("marks chunk load errors as handled once", () => {
    const error = Object.assign(
      new Error(
        "Loading chunk 5005 failed. (error: https://certping.example.com/_next/static/chunks/app/(global)/page.js)",
      ),
      { name: "ChunkLoadError" },
    );

    const { rerender } = render(<GlobalError error={error} reset={() => {}} />);

    expect(window.sessionStorage.length).toBe(1);

    rerender(<GlobalError error={error} reset={() => {}} />);

    expect(window.sessionStorage.length).toBe(1);
  });

  it("treats webpack module-resolution TypeErrors as chunk errors", () => {
    const error = Object.assign(
      new TypeError("Cannot read properties of undefined (reading 'call')"),
      {
        stack:
          "TypeError: Cannot read properties of undefined (reading 'call')\n" +
          "    at s (https://certping.com/_next/static/chunks/webpack-366f60a5d60a.js:1:144)\n" +
          "    at 14158 (https://certping.com/_next/static/chunks/app/(main)/cert-manager/discovery/page.js:1:5180)",
      },
    );

    render(<GlobalError error={error} reset={() => {}} />);

    expect(window.sessionStorage.length).toBe(1);
  });

  it("does not treat an app-code TypeError as a chunk error", () => {
    const error = Object.assign(
      new TypeError("Cannot read properties of undefined (reading 'name')"),
      {
        stack:
          "TypeError: Cannot read properties of undefined (reading 'name')\n" +
          "    at UserCard (https://certping.com/_next/static/chunks/app/dashboard/page.js:1:2048)",
      },
    );

    render(<GlobalError error={error} reset={() => {}} />);

    expect(window.sessionStorage.length).toBe(0);
  });
});
