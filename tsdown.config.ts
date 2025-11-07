import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['./src/auth.ts'],
  dts: true,
  format: ['cjs', 'esm']
})