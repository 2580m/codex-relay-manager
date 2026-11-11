'use strict';
// Local-only deterministic fixtures. No upstream requests and no dependencies.
const http = require('node:http');
const overrides = new Map();
const requests = [];
const sockets = new Set();
let sequence = 0;
const json = (res, status, value) => {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(value));
};
const event = (type, value) => `event: ${type}\r\ndata: ${JSON.stringify(value)}\r\n\r\n`;
const created = event('response.created', { type: 'response.created', response: { id: 'resp_mock', status: 'in_progress' } });
const progress = event('response.in_progress', { type: 'response.in_progress', response: { id: 'resp_mock', status: 'in_progress' } });
const delta = event('response.output_text.delta', { type: 'response.output_text.delta', delta: 'Hello 中文 ✓' });
const completed = event('response.completed', { type: 'response.completed', response: { id: 'resp_mock', status: 'completed', output: [] } });
function stream(res, text, interval = 6) {
  // Split raw UTF-8, including inside multi-byte code points and SSE lines.
  const bytes = Buffer.from(text);
  const widths = [1, 2, 7, 3, 13, 5, 19];
  let offset = 0;
  let index = 0;
  const send = () => {
    if (res.destroyed) return;
    if (offset >= bytes.length) return res.end();
    const next = Math.min(bytes.length, offset + widths[index++ % widths.length]);
    res.write(bytes.subarray(offset, next));
    offset = next;
    const timer = setTimeout(send, interval);
    timer.unref();
  };
  send();
}
function fixture(req, res, name, pathname) {
  const statusMatch = /^http-(401|403|404|429|500)$/.exec(name);
  if (statusMatch) {
    const status = Number(statusMatch[1]);
    if (status === 429) res.setHeader('retry-after', '1');
    return json(res, status, { error: { message: `Mock HTTP ${status}`, type: status === 429 ? 'rate_limit_error' : 'mock_error', code: String(status) } });
  }
  if (name === 'empty') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(); }
  if (name === 'nonjson') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end('<html>mock, not JSON or SSE</html>'); }
  if (name === 'timeout') {
    const timer = setTimeout(() => { if (!res.destroyed) json(res, 200, { data: [{ id: 'too-late' }] }); }, 2600);
    timer.unref();
    return;
  }
  if (/\/models\/?$/.test(pathname)) {
    switch (name) {
      case 'models-empty': return json(res, 200, { object: 'list', data: [] });
      case 'models-invalid': return json(res, 200, { unexpected: 'missing data array' });
      case 'models-duplicates': return json(res, 200, { data: [{ id: 'model-a' }, { id: 'model-a' }, { id: 'model-b' }] });
      case 'models-blank': return json(res, 200, { data: [{ id: 'model-a' }, { id: '' }, { id: '   ' }] });
      case 'models-nonstring': return json(res, 200, { data: [{ id: 123 }] });
      case 'models-b': return json(res, 200, { data: [{ id: 'provider-b-only' }] });
      case 'models-refreshed': return json(res, 200, { data: [{ id: 'model-new' }] });
      case 'models-context': return json(res, 200, {
        object: 'list',
        data: [
          { id: 'model-a', context_window: 1000000, max_context_window: 1000000, effective_context_window_percent: 95 },
          { id: 'model-b', context_length: 200000 },
          { id: 'model-openrouter', top_provider: { context_length: 1048576 } },
          { id: 'model-unit-k', context_length: '256K' },
          { id: 'model-no-meta' }
        ]
      });
      default: return json(res, 200, { object: 'list', data: [{ id: 'model-a', object: 'model' }, { id: 'model-b', object: 'model' }] });
    }
  }
  if (/\/responses\/?$/.test(pathname)) {
    if (name === 'json-response') return json(res, 200, { id: 'resp_json', status: 'completed', output: [{ type: 'message', content: [{ type: 'output_text', text: 'not a stream' }] }] });
    res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-cache', connection: 'keep-alive' });
    res.flushHeaders();
    const textSse = text => created + event('response.output_text.delta', { type: 'response.output_text.delta', delta: text }) + completed + 'data: [DONE]\r\n\r\n';
    switch (name) {
      case 'sse-lifecycle': return stream(res, ': heartbeat\r\n\r\n' + created + progress + completed + 'data: [DONE]\r\n\r\n');
      case 'sse-delta-only': return stream(res, created + delta + 'data: [DONE]\r\n\r\n');
      case 'sse-completed-only': return stream(res, completed);
      case 'sse-no-lifecycle': return stream(res, delta + completed);
      case 'sse-incomplete-status': return stream(res, created + delta + event('response.completed', { type: 'response.completed', response: { id: 'resp_mock', status: 'incomplete' } }));
      case 'sse-done-only': return stream(res, 'data: [DONE]\r\n\r\n');
      case 'sse-empty': return res.end();
      case 'sse-error': return stream(res, created + event('error', { type: 'error', error: { message: 'Mock stream error', code: 'mock_error' } }));
      case 'sse-failed': return stream(res, created + event('response.failed', { type: 'response.failed', response: { status: 'failed', error: { message: 'Mock response failed', code: 'mock_failed' } } }));
      case 'sse-error-then-completed': return stream(res, created + event('error', { type: 'error', message: 'Mock fatal error' }) + completed);
      case 'sse-malformed': return stream(res, 'event: response.output_text.delta\r\ndata: {broken json}\r\n\r\n' + completed);
      case 'sse-delayed': {
        res.write(created);
        const timer = setTimeout(() => { if (!res.destroyed) stream(res, delta + completed); }, 2600);
        timer.unref();
        return;
      }
      case 'sse-context-json': return stream(res, textSse(JSON.stringify({ models: [{ id: 'model-a', context_window: 1000000 }, { id: 'model-b', context_window: 200000 }, { id: 'model-no-meta', context_window: 512000 }] })));
      case 'sse-context-map': return stream(res, textSse(JSON.stringify({ models: { 'model-a': 1000000, 'model-unit-k': '256K', 'model-no-meta': null } })));
      case 'sse-context-scalar': return stream(res, textSse('1000000'));
      case 'sse-context-unit': return stream(res, textSse('1M'));
      case 'sse-context-invalid': return stream(res, textSse('Sorry, I think around 256K tokens.'));
      default: return stream(res, ': mock heartbeat\r\n\r\n' + created + delta + completed + 'data: [DONE]\r\n\r\n');
    }
  }
  json(res, 404, { error: { message: `Unknown mock route ${pathname}` } });
}
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  const chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', () => {
    const body = Buffer.concat(chunks).toString('utf8');
    if (url.pathname === '/__health') return json(res, 200, { ok: true, address: server.address() });
    if (url.pathname === '/__requests') return json(res, 200, { requests });
    if (url.pathname === '/__control' && req.method === 'POST') {
      let value;
      try { value = JSON.parse(body); } catch (_) { return json(res, 400, { error: 'Invalid control JSON' }); }
      if (value.reset) { requests.length = 0; overrides.clear(); }
      if (typeof value.key === 'string' && typeof value.fixture === 'string') overrides.set(value.key, value.fixture);
      return json(res, 200, { ok: true });
    }
    const authorization = req.headers.authorization || '';
    const key = authorization.replace(/^Bearer\s+/i, '');
    const pathFixture = /^\/fixture\/([^/]+)\//.exec(url.pathname);
    const tokenFixture = /^fixture:([a-z0-9-]+)/i.exec(key);
    const selected = overrides.get(key) || (pathFixture && pathFixture[1]) || (tokenFixture && tokenFixture[1]) || 'models-basic';
    requests.push({ sequence: ++sequence, method: req.method, path: url.pathname, authorization, headers: req.headers, body, fixture: selected });
    fixture(req, res, selected, url.pathname);
  });
});
server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
server.listen(0, '127.0.0.1', () => process.stdout.write(JSON.stringify({ port: server.address().port, host: '127.0.0.1', pid: process.pid }) + '\n'));
function stop() { for (const socket of sockets) socket.destroy(); server.close(() => process.exit(0)); }
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
