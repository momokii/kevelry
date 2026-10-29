import type { MetadataRoute } from "next";

const SITE_URL = (process.env.SITE_URL ?? "").trim().replace(/\/+$/, "") || "http://localhost:3000";

const ROUTES: Array<{ path: string; priority: number }> = [
  { path: "/", priority: 1 },
  { path: "/explore", priority: 0.9 },
  { path: "/priority", priority: 0.9 },
  { path: "/radar", priority: 0.7 },
  { path: "/replay", priority: 0.7 },
  { path: "/methodology", priority: 0.8 },
  { path: "/api-docs", priority: 0.6 },
];

export default function sitemap(): MetadataRoute.Sitemap {
  return ROUTES.map((route) => ({
    url: `${SITE_URL}${route.path}`,
    changeFrequency: "weekly",
    priority: route.priority,
  }));
}
