/** @jest-environment node */

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { NextRequest } from "next/server";

import {
  ClientLogRequestError,
  readClientLogMessage,
} from "@/app/web-api/logger/client-log-request";

describe("client log request reader", () => {
  it("stops reading an undeclared oversized stream", async () => {
    const cancel = jest.fn().mockResolvedValue(undefined);
    const request = {
      headers: new Headers({ "content-type": "application/json" }),
      body: {
        getReader: () => ({
          read: jest.fn().mockResolvedValue({
            done: false,
            value: new Uint8Array(32 * 1024 + 1),
          }),
          cancel,
        }),
      },
    } as unknown as NextRequest;

    await expect(readClientLogMessage(request)).rejects.toMatchObject({
      status: 413,
    });
    expect(cancel).toHaveBeenCalledTimes(1);
  });

  it("rejects an empty request body", async () => {
    const request = {
      headers: new Headers({ "content-type": "application/json" }),
      body: null,
    } as unknown as NextRequest;

    await expect(readClientLogMessage(request)).rejects.toBeInstanceOf(
      ClientLogRequestError,
    );
  });

  it("accepts application/json content type parameters", async () => {
    const body = JSON.stringify({ level: "info", message: "event" });
    const encodedBody = new TextEncoder().encode(body);
    const request = {
      headers: new Headers({
        "content-type": "application/json; charset=utf-8",
        "content-length": "not-a-number",
      }),
      body: {
        getReader: () => {
          let isRead = false;
          return {
            read: jest.fn().mockImplementation(async () => {
              if (isRead) return { done: true, value: undefined };
              isRead = true;
              return { done: false, value: encodedBody };
            }),
          };
        },
      },
    } as unknown as NextRequest;

    await expect(readClientLogMessage(request)).resolves.toEqual(
      expect.objectContaining({ level: "info", message: "event" }),
    );
  });
});
