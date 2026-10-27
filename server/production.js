import express from 'express';
import path from 'node:path';

/** Serve the built SPA after the API routes, including correct HEAD responses. */
export function attachProductionFrontend(app, dist) {
  app.use(express.static(dist, { index: false }));
  app.use((req, res, next) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') return next();
    return res.sendFile(path.join(dist, 'index.html'));
  });
}
