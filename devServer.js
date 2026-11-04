// Simple static file server for development (no external dependencies)
// Serves files from the repository directory on http://localhost:8000
// Usage: `node devServer.js`

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 8000;
const ROOT = __dirname; // repository root

// Minimal MIME type map
const mimeTypes = {
  '.html': 'text/html',
  '.css':  'text/css',
  '.js':   'application/javascript',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg':  'image/svg+xml',
  '.json': 'application/json',
  '.ico':  'image/x-icon'
};

const server = http.createServer((req, res) => {
  // Decode URL and prevent directory traversal
  const safeUrl = decodeURI(req.url).split('?')[0];
  let filePath = path.join(ROOT, safeUrl);
  // If URL ends with '/', serve index.html
  if (filePath.endsWith(path.sep)) {
    filePath = path.join(filePath, 'index.html');
  }

  fs.stat(filePath, (err, stats) => {
    if (err) {
      // Not found – try adding .html extension for clean URLs
      const htmlPath = filePath + '.html';
      fs.stat(htmlPath, (err2, stats2) => {
        if (err2) {
          res.writeHead(404, {'Content-Type':'text/plain'});
          res.end('404 Not Found');
          return;
        }
        serveFile(htmlPath, res);
      });
      return;
    }
    if (stats.isDirectory()) {
      // Serve index.html inside the directory
      const indexFile = path.join(filePath, 'index.html');
      fs.stat(indexFile, (e, s) => {
        if (e) {
          res.writeHead(403, {'Content-Type':'text/plain'});
          res.end('403 Forbidden');
          return;
        }
        serveFile(indexFile, res);
      });
    } else {
      serveFile(filePath, res);
    }
  });
});

function serveFile(filePath, res) {
  const ext = path.extname(filePath).toLowerCase();
  const mime = mimeTypes[ext] || 'application/octet-stream';
  const readStream = fs.createReadStream(filePath);
  res.writeHead(200, {'Content-Type': mime});
  readStream.pipe(res);
  readStream.on('error', () => {
    res.writeHead(500, {'Content-Type':'text/plain'});
    res.end('500 Internal Server Error');
  });
}

server.listen(PORT, () => {
  console.log(`⚡️ Development server running at http://localhost:${PORT}`);
});
