import { defineConfig } from "vite";
//import analyzer from "vite-bundle-analyzer";

// https://vite.dev/config/
export default defineConfig({
  build: {
    lib: {
      entry: "src/lib.ts",
      name: "hyli-noir",
      fileName: (format) => `hyli-noir.${format}.js`,
      formats: ["es", "cjs"],
    },
    rollupOptions: {
      external: ["@aztec/bb.js", "@noir-lang/noirc_abi", "@noir-lang/acvm_js"],
    },
    sourcemap: true,
    minify: true,
  },
  resolve: {
    alias: {
      "@": "./src",
    },
  },
  //plugins: [analyzer()],
});
