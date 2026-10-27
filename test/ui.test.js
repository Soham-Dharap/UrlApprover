import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { build } from 'esbuild';

test('landing page and all six tools render without runtime errors', async () => {
  const outputDir = await mkdtemp(
    path.join(process.cwd(), 'node_modules', '.cyberace-ui-test-'),
  );
  try {
    const pages = [
      ['Home', '/', 'A safer digital world'],
      ['UrlScanner', '/tools/url-scanner', 'Look before you link'],
      ['FileScanner', '/tools/file-scanner', 'File Scanner'],
      ['PasswordStudio', '/tools/password-studio', 'Password Studio'],
      ['EmailHeaders', '/tools/email-headers', 'Email Header Analyzer'],
      ['DomainInspector', '/tools/domain-inspector', 'Domain Inspector'],
      ['SecurityHeaders', '/tools/security-headers', 'Security Headers'],
    ];
    for (const [name, route, expected] of pages) {
      const outfile = path.join(outputDir, `${name}.mjs`);
      await build({
        stdin: {
          contents: `export { default as Page } from './src/pages/${name}.jsx'; export { StaticRouter } from 'react-router-dom';`,
          resolveDir: process.cwd(),
          loader: 'jsx',
        },
        outfile,
        bundle: true,
        platform: 'node',
        format: 'esm',
        jsx: 'automatic',
        external: ['react', 'react-dom', 'lucide-react', 'zxcvbn'],
        logLevel: 'silent',
      });
      const { Page, StaticRouter } = await import(pathToFileURL(outfile).href);
      const markup = renderToStaticMarkup(
        React.createElement(
          StaticRouter,
          { location: route },
          React.createElement(Page),
        ),
      );
      assert.ok(markup.includes(expected), `${name} should render its heading`);
    }
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
});
