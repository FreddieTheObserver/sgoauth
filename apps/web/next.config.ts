import type { NextConfig } from "next";

// The API is never addressed by the browser. Next proxies to it, so everything
// the user's browser sees is one origin on :3000 — which is what makes the
// cookies first-party, the `__Host-` prefix usable, and CORS unnecessary
// anywhere in this project.
const API_ORIGIN = process.env.API_ORIGIN ?? "http://localhost:4000";

const nextConfig: NextConfig = {
  images: {
    // Exactly the host Google serves avatars from, and nothing else. The image
    // optimizer fetches whatever this list allows, so a wildcard here would turn
    // /_next/image into an open proxy anyone could point at any URL.
    //
    // The avatar URL itself arrives in the `picture` claim of an ID token we
    // verified against Google's JWKS, so its host is not in doubt — this list is
    // what stops a later, looser source of image URLs from inheriting that trust.
    remotePatterns: [{ protocol: "https", hostname: "lh3.googleusercontent.com" }],
  },

  async rewrites() {
    return [
      {
        // /api/auth/google → http://localhost:4000/auth/google
        //
        // The `/api` prefix is stripped: it exists to carve out a namespace in
        // the browser-visible URL space, and Nest's own routes do not carry it.
        // This is also why GOOGLE_REDIRECT_URI is registered on port 3000 and
        // not 4000 — Google redirects the browser, and the browser only knows
        // about this origin.
        source: "/api/:path*",
        destination: `${API_ORIGIN}/:path*`,
      },
    ];
  },
};

export default nextConfig;
