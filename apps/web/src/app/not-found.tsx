// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import "./globals.css";
import { ShieldSlashIcon } from "@phosphor-icons/react/dist/ssr";
import { Card, CardHeader, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import Link from "next/link";

export default function NotFound() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background px-4">
      <Card className="mx-auto w-full max-w-md border">
        <CardHeader className="flex flex-col items-center gap-2 pb-2">
          <div className="relative mb-2">
            <ShieldSlashIcon className="h-14 w-14 text-destructive" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">
            404: Page Not Found
          </h1>
        </CardHeader>
        <CardContent className="flex flex-col items-center gap-4">
          <p className="text-center text-base text-muted-foreground">
            Looks like you've reached a page that doesn't exist.
            <br />
            The page you're looking for isn't here, but your security is.
          </p>
          <div className="flex w-full justify-center gap-2">
            <Button asChild>
              <Link href="/login">Go to sign in</Link>
            </Button>
          </div>
        </CardContent>
      </Card>
      <footer className="mt-8 text-xs text-muted-foreground">
        &copy; {new Date().getFullYear()} Seaionl Inc. CertPing is open source
        software under the Apache License 2.0.
      </footer>
    </div>
  );
}
