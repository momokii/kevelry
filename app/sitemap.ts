import type { MetadataRoute } from "next";

// Request-time: the origin must come from the container's runtime environment.
// A prerendered sitemap bakes whatever SITE_URL the image was built with — on
// the published image that is unset — and would keep advertising localhost
// after deployment. A blank SITE_URL keeps the localhost fallback for private
// development use.
export const dynamic = "force-dynamic";

const ROUTES: Array<{ path: string; priority: number }> = [
  { path: "/", priority: 1 },
  { path: "/explore", priority: 0.9 },
  { path: "/priority", priority: 0.9 },
  { path: "/radar", priority: 0.7 },
  { path: "/replay", priority: 0.7 },
  { path: "/methodology", priority: 0.8 },
  { path: "/api-docs", priority: 0.6 },
  { path: "/watch", priority: 0.4 },
  { path: "/graph", priority: 0.5 },
];

export default function sitemap(): MetadataRoute.Sitemap {
  const siteUrl =
    (process.env.SITE_URL ?? "").trim().replace(/\/+$/, "") || "http://localhost:3000";
  return ROUTES.map((route) => ({
    url: `${siteUrl}${route.path}`,
    changeFrequency: "weekly",
    priority: route.priority,
  }));
}
