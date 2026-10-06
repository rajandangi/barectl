import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { defineConfig, type Plugin } from "vite-plus";

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
  fmt: {
    // docs/quality.md#frontend-policy
    ignorePatterns: [
      "templates/**",
      "**/*.md",
      "**/*.toml",
      "docker/disposable-server/durations.json",
    ],
  },
  lint: {
    categories: {
      correctness: "error",
    },
    options: {
      typeAware: true,
      typeCheck: true,
      reportUnusedDisableDirectives: "error",
    },
    jsPlugins: [
      {
        name: "vite-plus",
        specifier: "vite-plus/oxlint-plugin",
      },
    ],
    rules: {
      "vite-plus/prefer-vite-plus-imports": "error",
      "no-case-declarations": "error",
      "no-empty": "error",
      "no-fallthrough": "error",
      "no-prototype-builtins": "error",
      "no-redeclare": "error",
      "no-regex-spaces": "error",
      "no-undef": "error",
      "no-unexpected-multiline": "error",
      "no-useless-assignment": "error",
      "preserve-caught-error": "error",
      "no-array-constructor": "error",
      "no-useless-constructor": "error",
      "typescript/ban-ts-comment": [
        "error",
        {
          "ts-expect-error": "allow-with-description",
          "ts-ignore": true,
          "ts-nocheck": true,
          minimumDescriptionLength: 10,
        },
      ],
      "typescript/no-confusing-void-expression": "error",
      "typescript/no-deprecated": "error",
      "typescript/no-dynamic-delete": "error",
      "typescript/no-empty-object-type": "error",
      "typescript/no-explicit-any": "error",
      "typescript/no-extraneous-class": "error",
      "typescript/no-floating-promises": [
        "error",
        {
          ignoreVoid: false,
        },
      ],
      "typescript/no-invalid-void-type": "error",
      "typescript/no-misused-promises": "error",
      "typescript/no-mixed-enums": "error",
      "typescript/no-namespace": "error",
      "typescript/no-non-null-asserted-nullish-coalescing": "error",
      "typescript/no-non-null-assertion": "error",
      "typescript/no-require-imports": "error",
      "typescript/no-unnecessary-boolean-literal-compare": "error",
      "typescript/no-unnecessary-condition": "error",
      "typescript/no-unnecessary-template-expression": "error",
      "typescript/no-unnecessary-type-arguments": "error",
      "typescript/no-unnecessary-type-assertion": "error",
      "typescript/no-unnecessary-type-constraint": "error",
      "typescript/no-unnecessary-type-conversion": "error",
      "typescript/no-unnecessary-type-parameters": "error",
      "typescript/no-unsafe-argument": "error",
      "typescript/no-unsafe-assignment": "error",
      "typescript/no-unsafe-call": "error",
      "typescript/no-unsafe-enum-comparison": "error",
      "typescript/no-unsafe-function-type": "error",
      "typescript/no-unsafe-member-access": "error",
      "typescript/no-unsafe-return": "error",
      "typescript/only-throw-error": "error",
      "typescript/prefer-literal-enum-member": "error",
      "typescript/prefer-promise-reject-errors": "error",
      "typescript/prefer-reduce-type-parameter": "error",
      "typescript/prefer-return-this-type": "error",
      "typescript/related-getter-setter-pairs": "error",
      "typescript/require-await": "error",
      "typescript/restrict-plus-operands": [
        "error",
        {
          allowAny: false,
          allowBoolean: false,
          allowNullish: false,
          allowNumberAndString: false,
          allowRegExp: false,
        },
      ],
      "typescript/restrict-template-expressions": [
        "error",
        {
          allowAny: false,
          allowBoolean: false,
          allowNever: false,
          allowNullish: false,
          allowNumber: false,
          allowRegExp: false,
        },
      ],
      "typescript/return-await": ["error", "error-handling-correctness-only"],
      "typescript/unified-signatures": "error",
      "typescript/use-unknown-in-catch-callback-variable": "error",
      "no-console": "error",
      "typescript/switch-exhaustiveness-check": "error",
      "typescript/explicit-function-return-type": "error",
    },
    overrides: [
      {
        // docs/quality.md#frontend-policy
        files: ["**/*.{ts,mts,cts}"],
        rules: {
          "no-redeclare": "off",
          "no-undef": "off",
          "no-var": "error",
          "prefer-const": "error",
          "prefer-rest-params": "error",
          "prefer-spread": "error",
        },
      },
    ],
  },
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
