import { readFileSync } from 'node:fs';
import { defineConfig } from 'vite';

// Test the static preview with the same response headers configured for Vercel.
const vercel = JSON.parse(readFileSync('vercel.json', 'utf8'));
const headers = Object.fromEntries(vercel.headers[0].headers.map(({ key, value }: { key: string; value: string }) => [key, value]));
export default defineConfig({ preview: { headers } });
