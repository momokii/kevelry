import type { MetadataRoute } from "next";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: "*",
        allow: ["/"],
        // The versioned API serves machines, not crawlers; /showcase is a
        // component gallery with synthetic fixtures, not real data.
        disallow: ["/api/", "/showcase"],
      },
    ],
  };
}
