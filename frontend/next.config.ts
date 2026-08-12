import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  allowedDevOrigins: ["172.16.22.220"],
  experimental: {
    useTypeScriptCli: false,
  },
};

export default nextConfig;
