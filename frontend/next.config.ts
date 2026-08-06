import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  allowedDevOrigins: ["172.16.22.220"],
  experimental: {
    useTypeScriptCli: false,
  },
};

export default nextConfig;
