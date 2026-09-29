import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { defineConfig, type Plugin } from "vite";

const frontendRoot = fileURLToPath(new URL("frontend", import.meta.url));
const mainEntry = fileURLToPath(new URL("frontend/main.ts", import.meta.url));
const uswdsInitEntry = fileURLToPath(new URL("frontend/uswds-init.ts", import.meta.url));
const nodeModules = fileURLToPath(new URL("node_modules", import.meta.url));
const outDir = fileURLToPath(new URL("static/dist", import.meta.url));
const uswdsPackages = fileURLToPath(new URL("node_modules/@uswds/uswds/packages", import.meta.url));
// Browser tests start a second development server on a free port.
const devServerPort = Number(process.env["BARECTL_VITE_DEV_PORT"] ?? "5173");
if (!Number.isInteger(devServerPort) || devServerPort < 1 || devServerPort > 65535) {
  throw new Error("BARECTL_VITE_DEV_PORT must be a TCP port number.");
}

/** docs/frontend-assets.md#licenses */
function fontLicense(): Plugin {
  const license = fileURLToPath(
    new URL("node_modules/@fontsource-variable/inter/LICENSE", import.meta.url),
  );
  return {
    name: "barectl-font-license",
    apply: "build",
    async generateBundle(): Promise<void> {
      this.emitFile({
        type: "asset",
        fileName: "licenses/inter-ofl.txt",
        source: await readFile(license, "utf8"),
      });
    },
  };
}

// docs/frontend-assets.md#development-and-production
export default defineConfig(({ command }) => ({
  root: frontendRoot,
  plugins: [fontLicense()],
  base: command === "build" ? "./" : "/",
  css: {
    preprocessorOptions: {
      scss: {
        // USWDS packages and packages without Sass exports, such as Fontsource metadata.
        loadPaths: [uswdsPackages, nodeModules],
      },
    },
  },
  server: {
    port: devServerPort,
    strictPort: true,
    origin: `http://localhost:${String(devServerPort)}`,
    fs: {
      // Serve only browser sources and installed packages, never the repository root.
      allow: [frontendRoot, nodeModules],
    },
  },
  build: {
    outDir,
    emptyOutDir: true,
    manifest: true,
    license: { fileName: "licenses/dependencies.md" },
    modulePreload: { polyfill: false },
    rolldownOptions: {
      input: [uswdsInitEntry, mainEntry],
    },
  },
}));
