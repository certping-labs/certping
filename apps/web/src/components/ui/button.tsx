// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { CircleNotchIcon } from "@phosphor-icons/react/dist/ssr";

import { MorphText } from "@/components/ui/morph-text";
import { cn } from "@/lib/utils";

/**
 * Wraps each run of text children in MorphText so a label swap morphs.
 * Whitespace-only runs stay plain: a flex container drops them anyway.
 */
function morphTextRuns(children: React.ReactNode): React.ReactNode {
  if (typeof children === "string" || typeof children === "number") {
    const text = String(children).trim();
    return text ? <MorphText>{text}</MorphText> : children;
  }
  if (!Array.isArray(children)) return children;

  const out: React.ReactNode[] = [];
  let text = "";
  let run = 0;
  const flush = () => {
    if (text.trim()) {
      out.push(<MorphText key={`morph-${run}`}>{text.trim()}</MorphText>);
      run += 1;
    } else if (text) {
      out.push(text);
    }
    text = "";
  };
  for (const node of React.Children.toArray(children)) {
    if (typeof node === "string" || typeof node === "number") {
      text += node;
    } else {
      flush();
      out.push(node);
    }
  }
  flush();
  return out;
}

const buttonVariants = cva(
  "inline-flex select-none items-center justify-center gap-2 whitespace-nowrap rounded-full border text-sm font-medium tracking-[-0.01em] focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:pointer-events-none aria-disabled:cursor-not-allowed [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default: "mg-btn mg-btn-primary border-transparent",
        destructive: "mg-btn mg-btn-danger border-transparent",
        outline: "mg-btn mg-btn-outline border-transparent",
        soft: "mg-btn mg-btn-tonal border-transparent",
        secondary: "mg-btn mg-btn-neutral border-transparent",
        ghost:
          "mg-btn border-transparent bg-transparent text-muted-foreground hover:text-foreground",
        subtle:
          "border-transparent px-0 py-0 text-primary transition-colors hover:text-primary-hover disabled:opacity-50",
        link: "rounded-none border-0 px-0 text-primary underline-offset-4 hover:underline disabled:opacity-50",
        icon: "mg-btn mg-btn-neutral border-transparent text-muted-foreground hover:text-foreground",
        iconSm:
          "mg-btn border-transparent bg-transparent p-0 text-muted-foreground hover:text-foreground",
      },
      size: {
        default: "h-10 px-5",
        sm: "h-8 px-3.5 text-xs",
        lg: "h-11 px-6 text-[15px]",
        icon: "h-9 w-9 px-0",
        iconSm: "h-8 w-8 p-0",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

export interface ButtonProps
  extends
    React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
  isPending?: boolean;
  loadingtext?: string;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      className,
      variant,
      size,
      asChild = false,
      isPending = false,
      loadingtext,
      children,
      ...props
    },
    ref,
  ) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        data-variant={variant ?? "default"}
        aria-busy={isPending || undefined}
        {...props}
      >
        {asChild ? (
          children
        ) : (
          <>
            {isPending && (
              <CircleNotchIcon
                className="mg-btn-spinner animate-spin"
                aria-hidden
              />
            )}
            {morphTextRuns(isPending && loadingtext ? loadingtext : children)}
          </>
        )}
      </Comp>
    );
  },
);
Button.displayName = "Button";

export { Button, buttonVariants };
