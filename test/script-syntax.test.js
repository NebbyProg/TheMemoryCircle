import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

test('camera-engine.js syntax and evaluation validity', () => {
  const code = fs.readFileSync('camera-engine.js', 'utf8');
  assert.doesNotThrow(() => {
    new vm.Script(code);
  });
});

test('script.js syntax validity', () => {
  const code = fs.readFileSync('script.js', 'utf8');
  assert.doesNotThrow(() => {
    new vm.Script(code);
  });
});

test('index.html references camera-engine.js before script.js', () => {
  const html = fs.readFileSync('index.html', 'utf8');
  const engineIdx = html.indexOf('src="./camera-engine.js"');
  const scriptIdx = html.indexOf('src="./script.js"');
  assert.ok(engineIdx > 0, 'index.html must reference camera-engine.js');
  assert.ok(scriptIdx > 0, 'index.html must reference script.js');
  assert.ok(engineIdx < scriptIdx, 'camera-engine.js must be loaded before script.js');
});

test('index.html has eye-af-overlay and btn-toggle-eye-af', () => {
  const html = fs.readFileSync('index.html', 'utf8');
  assert.ok(html.includes('id="eye-af-overlay"'), 'index.html must include eye-af-overlay');
  assert.ok(html.includes('id="btn-toggle-eye-af"'), 'index.html must include btn-toggle-eye-af');
  assert.ok(html.includes('id="eye-af-badge"'), 'index.html must include eye-af-badge');
});
