// Vercel adapter: the platform posts to /api/agent on this deployment; the
// gatekeeper server routes on /agent, so translate the path and hand the
// request to the same http.Server the local entrypoint listens on.
import { server } from '../server.mjs';

export default function handler(req, res) {
  if (req.url === '/api/agent' || req.url.startsWith('/api/agent?')) {
    req.url = req.url.replace('/api/agent', '/agent');
  } else if (req.url === '/api/health' || req.url.startsWith('/api/health?')) {
    req.url = req.url.replace('/api/health', '/health');
  }
  server.emit('request', req, res);
}
