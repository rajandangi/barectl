import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { defineConfig, type Plugin } from "vite";

const frontendRoot = fileURLToPath(new URL("frontend", import.meta.url));
const mainEntry = fileURLToPath(new URL("frontend/main.ts", import.meta.url));
const uswdsInitEntry = fileURLToPath(new URL("frontend/uswds-init.ts", import.meta.url));
const nodeModules = fileURLToPath(new URL("node_modules", import.meta.url));
const outDir = fileURLToPath(new URL("static/dist", import.meta.url));
const uswdsPackages = fileURLToPath(new URL("node_modules/@uswds/uswds/packages", import.meta.url));
const devServerPort = 5173;

/**
 * Vite's license file covers bundled modules. Inter reaches the build only as font assets,
 * so ship its SIL Open Font License beside it.
 */
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

// Django renders the HTML. Vite serves development modules and writes the production
// manifest that the `vite_entry` template tag reads. See docs/frontend-assets.md.
export default defineConfig(({ command }) => ({
  root: frontendRoot,
  plugins: [fontLicense()],
  // Relative URLs keep built CSS fonts and chunk imports independent of STATIC_URL.
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
