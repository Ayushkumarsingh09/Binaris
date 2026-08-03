import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  output: "standalone",
  images: {
    unoptimized: true,
  },
  async rewrites() {
    const api = process.env.BINARIS_API_URL ?? "http://127.0.0.1:8080";
    return [
      {
        source: "/api/:path*",
        destination: `${api}/:path*`,
      },
    ];
  },
};

export default nextConfig;
