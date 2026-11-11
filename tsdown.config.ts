import { defineConfig } from 'tsdown'

/**
 * Host half: one self-contained ESM file with execa and yaml inlined, so installing the plugin adds no runtime
 * dependencies to the profile. Browser half: CommonJS whose externals the DSH page module table provides; the wrap
 * script turns it into the loader factory the page expects.
 */
export default defineConfig([
  {
    entry: { index: 'src/host/index.ts' },
    outDir: 'lib',
    format: ['esm'],
    platform: 'node',
    target: 'node24',
    fixedExtension: false,
    dts: false,
    clean: false,
    noExternal: ['execa', 'yaml'],
    deps: { onlyAllowBundle: false },
  },
  {
    entry: { 'client.raw': 'src/client/index.ts' },
    outDir: 'lib',
    format: ['cjs'],
    platform: 'browser',
    target: 'es2022',
    fixedExtension: false,
    dts: false,
    clean: false,
    external: [/^react($|\/)/, /^react-dom($|\/)/, /^@deepseek-ai\//],
    deps: { onlyAllowBundle: false },
  },
])
