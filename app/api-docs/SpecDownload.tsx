"use client";

// Client island for the spec download. The full openapi/v1.yaml text is
// passed from the server component (read on each request from the repo file),
// so the download matches the rendered table byte-for-byte without a new
// route or a public/ copy. Offline-safe: no CDN, just a Blob URL.

import { useEffect, useState } from "react";

export function SpecDownload({ specText }: { specText: string }) {
  const [href, setHref] = useState<string | null>(null);

  useEffect(() => {
    const url = URL.createObjectURL(new Blob([specText], { type: "text/yaml" }));
    setHref(url);
    return () => URL.revokeObjectURL(url);
  }, [specText]);

  if (href === null) {
    return (
      <span className="ledger-meta" data-testid="api-docs-spec-pending">
        Preparing openapi/v1.yaml download…
      </span>
    );
  }
  return (
    <a
      className="ledger-more-link"
      data-testid="api-docs-spec-download"
      download="v1.yaml"
      href={href}
    >
      Download openapi/v1.yaml ({specText.length} bytes)
    </a>
  );
}
