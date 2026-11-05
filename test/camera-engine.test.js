import test from 'node:test';
import assert from 'node:assert/strict';

// Import CameraEngine (which doesn't have computeCoverCrop yet or file doesn't exist yet)
import { CameraEngine } from '../camera-engine.js';

test('CameraEngine.computeCoverCrop - crops width when source is wider than target (e.g. 16:9 into 1:1 polaroid)', () => {
  // Source: 1920x1080 (16:9 ~ 1.777)
  // Target cell: 600x600 (1:1 = 1.0)
  // Expected: target ratio is 1.0, so sh = 1080, sw = 1080.
  // With focalX = 0.5 (center), sx = (1920 - 1080) / 2 = 420, sy = 0.
  const crop = CameraEngine.computeCoverCrop({
    sourceWidth: 1920,
    sourceHeight: 1080,
    targetWidth: 600,
    targetHeight: 600,
    focalX: 0.5,
    focalY: 0.5
  });

  assert.equal(crop.sw, 1080);
  assert.equal(crop.sh, 1080);
  assert.equal(crop.sx, 420);
  assert.equal(crop.sy, 0);
});

test('CameraEngine.computeCoverCrop - crops height when source is taller than target (e.g. mobile 3:4 into landscape 4-cut cell)', () => {
  // Source: 3000x4000 (3:4 = 0.75)
  // Target cell: 600x400 (3:2 = 1.5)
  // Expected: sw = 3000, sh = 3000 / 1.5 = 2000.
  // With focalY = 0.3 (eye level in upper third):
  // idealY = 4000 * 0.3 - 2000 / 2 = 1200 - 1000 = 200.
  const crop = CameraEngine.computeCoverCrop({
    sourceWidth: 3000,
    sourceHeight: 4000,
    targetWidth: 600,
    targetHeight: 400,
    focalX: 0.5,
    focalY: 0.3
  });

  assert.equal(crop.sw, 3000);
  assert.equal(crop.sh, 2000);
  assert.equal(crop.sx, 0);
  assert.equal(crop.sy, 200);
});

test('CameraEngine.computeCoverCrop - clamps crop boundaries when focal point is near top or bottom edges', () => {
  // Extreme top focalY = 0.0 -> sy should clamp to 0, not negative
  const topCrop = CameraEngine.computeCoverCrop({
    sourceWidth: 1000,
    sourceHeight: 2000,
    targetWidth: 500,
    targetHeight: 500,
    focalY: 0.0
  });
  assert.equal(topCrop.sy, 0);

  // Extreme bottom focalY = 1.0 -> sy should clamp to sourceHeight - sh
  const bottomCrop = CameraEngine.computeCoverCrop({
    sourceWidth: 1000,
    sourceHeight: 2000,
    targetWidth: 500,
    targetHeight: 500,
    focalY: 1.0
  });
  assert.equal(bottomCrop.sy, 1000);
});

test('CameraEngine.detectPupilsFromLuminance - detects left and right eye coordinates from facial luminance map', () => {
  const width = 160;
  const height = 120;
  // Create RGBA buffer (width * height * 4)
  const rgba = new Uint8ClampedArray(width * height * 4);

  // Fill with typical skin tone background (R: 220, G: 180, B: 160)
  for (let i = 0; i < rgba.length; i += 4) {
    rgba[i] = 220;     // R
    rgba[i + 1] = 180; // G
    rgba[i + 2] = 160; // B
    rgba[i + 3] = 255; // A
  }

  // Draw dark left eye pupil/iris around (50, 45), radius 4
  // Draw dark right eye pupil/iris around (110, 45), radius 4
  const drawDarkSpot = (cx, cy, r) => {
    for (let dy = -r; dy <= r; dy++) {
      for (let dx = -r; dx <= r; dx++) {
        if (dx * dx + dy * dy <= r * r) {
          const idx = ((cy + dy) * width + (cx + dx)) * 4;
          rgba[idx] = 20;     // Dark iris R
          rgba[idx + 1] = 20; // G
          rgba[idx + 2] = 25; // B
        }
      }
    }
  };

  drawDarkSpot(50, 45, 4);
  drawDarkSpot(110, 45, 4);

  const result = CameraEngine.detectPupilsFromRGBA(rgba, width, height);

  assert.equal(result.detected, true);
  assert.ok(Math.abs(result.leftEye.x - 50) <= 8, `Expected leftEye.x near 50, got ${result.leftEye.x}`);
  assert.ok(Math.abs(result.leftEye.y - 45) <= 8, `Expected leftEye.y near 45, got ${result.leftEye.y}`);
  assert.ok(Math.abs(result.rightEye.x - 110) <= 8, `Expected rightEye.x near 110, got ${result.rightEye.x}`);
  assert.ok(Math.abs(result.rightEye.y - 45) <= 8, `Expected rightEye.y near 45, got ${result.rightEye.y}`);
  assert.ok(result.leftEye.box.width > 0);
  assert.ok(result.rightEye.box.width > 0);
});

test('CameraEngine.detectPupilsFromRGBA - returns detected:false with graceful fallback when no eyes exist', () => {
  const width = 160;
  const height = 120;
  const rgba = new Uint8ClampedArray(width * height * 4).fill(255); // completely blank white

  const result = CameraEngine.detectPupilsFromRGBA(rgba, width, height);

  assert.equal(result.detected, false);
  assert.ok(result.midpoint.x > 0);
  assert.ok(result.midpoint.y > 0);
});

test('CameraEngine.applySharpnessFilter - sharpens edge contrast while clamping to [0, 255]', () => {
  const width = 5;
  const height = 5;
  const rgba = new Uint8ClampedArray(width * height * 4);

  // Initialize a smooth vertical step edge in column 2
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const idx = (y * width + x) * 4;
      const val = x < 2 ? 100 : 160;
      rgba[idx] = val;     // R
      rgba[idx + 1] = val; // G
      rgba[idx + 2] = val; // B
      rgba[idx + 3] = 255; // A
    }
  }

  // Before sharpening: edge difference between col 1 (100) and col 2 (160) is 60
  const centerIdxCol1 = (2 * width + 1) * 4;
  const centerIdxCol2 = (2 * width + 2) * 4;
  const beforeDiff = rgba[centerIdxCol2] - rgba[centerIdxCol1];
  assert.equal(beforeDiff, 60);

  const sharpened = CameraEngine.applySharpnessFilter(rgba, width, height, { amount: 0.8 });

  // After sharpening: edge contrast should be enhanced (greater than 60)
  const afterDiff = sharpened[centerIdxCol2] - sharpened[centerIdxCol1];
  assert.ok(afterDiff > beforeDiff, `Expected sharpened diff > ${beforeDiff}, got ${afterDiff}`);

  // All pixels must be valid bytes within 0-255 and alpha preserved
  for (let i = 0; i < sharpened.length; i += 4) {
    assert.ok(sharpened[i] >= 0 && sharpened[i] <= 255);
    assert.ok(sharpened[i + 1] >= 0 && sharpened[i + 1] <= 255);
    assert.ok(sharpened[i + 2] >= 0 && sharpened[i + 2] <= 255);
    assert.equal(sharpened[i + 3], 255);
  }
});

test('CameraEngine.drawImageCover - draws source into canvas context using computed cover crop', () => {
  let recordedArgs = null;
  const mockCtx = {
    drawImage: (...args) => {
      recordedArgs = args;
    }
  };

  const mockSource = { width: 1920, height: 1080 };
  CameraEngine.drawImageCover(mockCtx, mockSource, 10, 20, 400, 400, 0.5, 0.5);

  assert.ok(recordedArgs, 'drawImage should have been called');
  assert.equal(recordedArgs[0], mockSource);
  // sx, sy, sw, sh
  assert.equal(recordedArgs[1], 420); // sx
  assert.equal(recordedArgs[2], 0);   // sy
  assert.equal(recordedArgs[3], 1080);// sw
  assert.equal(recordedArgs[4], 1080);// sh
  // dx, dy, dw, dh
  assert.equal(recordedArgs[5], 10);
  assert.equal(recordedArgs[6], 20);
  assert.equal(recordedArgs[7], 400);
  assert.equal(recordedArgs[8], 400);
});




