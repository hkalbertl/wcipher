import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["cjs", "esm"], // Generate both CommonJS and ESM
  dts: true, // Generate TypeScript definitions
  clean: true, // Clean the dist folder before building
  minify: true, // Minify output for smaller file size
});
