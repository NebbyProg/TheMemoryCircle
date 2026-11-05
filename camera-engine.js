/**
 * CameraEngine - Core algorithms for aspect-ratio cover-crop,
 * eye detection, and sharpness enhancement.
 * Universal Module (supports browser vanilla <script>, ES Modules, and CommonJS/Node).
 * Zero external dependencies.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    const exported = factory();
    module.exports = exported;
    module.exports.CameraEngine = exported;
  } else if (typeof define === 'function' && define.amd) {
    define(factory);
  } else {
    root.CameraEngine = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const CameraEngine = {
    /**
     * Compute source crop parameters (sx, sy, sw, sh) that preserve
     * source aspect ratio inside a target dimension (object-fit: cover).
     *
     * @param {Object} options
     * @param {number} options.sourceWidth
     * @param {number} options.sourceHeight
     * @param {number} options.targetWidth
     * @param {number} options.targetHeight
     * @param {number} [options.focalX=0.5] - Normalized focal center X (0 to 1)
     * @param {number} [options.focalY=0.4] - Normalized focal center Y (0 to 1)
     * @returns {{sx: number, sy: number, sw: number, sh: number}}
     */
    computeCoverCrop({
      sourceWidth,
      sourceHeight,
      targetWidth,
      targetHeight,
      focalX = 0.5,
      focalY = 0.4
    }) {
      const srcRatio = sourceWidth / sourceHeight;
      const tgtRatio = targetWidth / targetHeight;

      let sx = 0;
      let sy = 0;
      let sw = sourceWidth;
      let sh = sourceHeight;

      if (srcRatio > tgtRatio) {
        // Source is wider than target: fit height, crop width
        sh = sourceHeight;
        sw = Math.round(sourceHeight * tgtRatio);
        const idealX = sourceWidth * focalX - sw / 2;
        sx = Math.max(0, Math.min(sourceWidth - sw, Math.round(idealX)));
      } else if (srcRatio < tgtRatio) {
        // Source is taller than target: fit width, crop height
        sw = sourceWidth;
        sh = Math.round(sourceWidth / tgtRatio);
        const idealY = sourceHeight * focalY - sh / 2;
        sy = Math.max(0, Math.min(sourceHeight - sh, Math.round(idealY)));
      }

      return { sx, sy, sw, sh };
    },

    /**
     * Draw an image or canvas into target rectangle with cover aspect ratio,
     * completely preventing stretching.
     */
    drawImageCover(ctx, img, dx, dy, dw, dh, focalX = 0.5, focalY = 0.4) {
      const sourceWidth = img.videoWidth || img.naturalWidth || img.width;
      const sourceHeight = img.videoHeight || img.naturalHeight || img.height;

      const { sx, sy, sw, sh } = this.computeCoverCrop({
        sourceWidth,
        sourceHeight,
        targetWidth: dw,
        targetHeight: dh,
        focalX,
        focalY
      });

      ctx.drawImage(img, sx, sy, sw, sh, dx, dy, dw, dh);
    },

    /**
     * Fast luminance-contrast pupil and eye detector from RGBA image buffer.
     * Runs in O(N) time with zero external dependencies.
     *
     * @param {Uint8ClampedArray|Uint8Array} rgba
     * @param {number} width - buffer width (e.g. 160)
     * @param {number} height - buffer height (e.g. 120)
     * @returns {{
     *   detected: boolean,
     *   leftEye: { x: number, y: number, box: { x: number, y: number, width: number, height: number } },
     *   rightEye: { x: number, y: number, box: { x: number, y: number, width: number, height: number } },
     *   midpoint: { x: number, y: number },
     *   confidence: number
     * }}
     */
    detectPupilsFromRGBA(rgba, width, height) {
      const fallbackMidpoint = { x: Math.round(width * 0.5), y: Math.round(height * 0.38) };
      const defaultBoxSize = Math.max(14, Math.round(width * 0.12));

      // Define search region for eyes (upper facial region)
      const minY = Math.round(height * 0.15);
      const maxY = Math.round(height * 0.65);
      const minLeftX = Math.round(width * 0.15);
      const maxLeftX = Math.round(width * 0.48);
      const minRightX = Math.round(width * 0.52);
      const maxRightX = Math.round(width * 0.85);

      // Compute luminance map for the region
      let minLeftLum = 255;
      let minLeftXPos = fallbackMidpoint.x - Math.round(width * 0.18);
      let minLeftYPos = fallbackMidpoint.y;
      let leftSumLum = 0;
      let leftCount = 0;

      let minRightLum = 255;
      let minRightXPos = fallbackMidpoint.x + Math.round(width * 0.18);
      let minRightYPos = fallbackMidpoint.y;
      let rightSumLum = 0;
      let rightCount = 0;

      for (let y = minY; y <= maxY; y++) {
        const rowOffset = y * width;
        for (let x = minLeftX; x <= maxRightX; x++) {
          const idx = (rowOffset + x) * 4;
          const lum = 0.299 * rgba[idx] + 0.587 * rgba[idx + 1] + 0.114 * rgba[idx + 2];

          if (x <= maxLeftX) {
            leftSumLum += lum;
            leftCount++;
            if (lum < minLeftLum) {
              minLeftLum = lum;
              minLeftXPos = x;
              minLeftYPos = y;
            }
          } else if (x >= minRightX) {
            rightSumLum += lum;
            rightCount++;
            if (lum < minRightLum) {
              minRightLum = lum;
              minRightXPos = x;
              minRightYPos = y;
            }
          }
        }
      }

      const leftAvgLum = leftCount > 0 ? leftSumLum / leftCount : 128;
      const rightAvgLum = rightCount > 0 ? rightSumLum / rightCount : 128;

      const leftContrast = leftAvgLum - minLeftLum;
      const rightContrast = rightAvgLum - minRightLum;

      // Verify plausible eye geometry
      const minContrastRequired = 30;
      const yDelta = Math.abs(minLeftYPos - minRightYPos);
      const xDistance = minRightXPos - minLeftXPos;
      const isPlausible =
        leftContrast >= minContrastRequired &&
        rightContrast >= minContrastRequired &&
        yDelta <= height * 0.2 &&
        xDistance >= width * 0.15 &&
        xDistance <= width * 0.65;

      if (isPlausible) {
        const boxSize = defaultBoxSize;
        const halfBox = Math.round(boxSize / 2);

        return {
          detected: true,
          leftEye: {
            x: minLeftXPos,
            y: minLeftYPos,
            box: {
              x: Math.max(0, minLeftXPos - halfBox),
              y: Math.max(0, minLeftYPos - halfBox),
              width: boxSize,
              height: boxSize
            }
          },
          rightEye: {
            x: minRightXPos,
            y: minRightYPos,
            box: {
              x: Math.max(0, minRightXPos - halfBox),
              y: Math.max(0, minRightYPos - halfBox),
              width: boxSize,
              height: boxSize
            }
          },
          midpoint: {
            x: Math.round((minLeftXPos + minRightXPos) / 2),
            y: Math.round((minLeftYPos + minRightYPos) / 2)
          },
          confidence: Math.min(1.0, (leftContrast + rightContrast) / 160)
        };
      }

      // Fallback when no high-contrast eyes are detected
      const halfBox = Math.round(defaultBoxSize / 2);
      return {
        detected: false,
        leftEye: {
          x: fallbackMidpoint.x - Math.round(width * 0.18),
          y: fallbackMidpoint.y,
          box: {
            x: fallbackMidpoint.x - Math.round(width * 0.18) - halfBox,
            y: fallbackMidpoint.y - halfBox,
            width: defaultBoxSize,
            height: defaultBoxSize
          }
        },
        rightEye: {
          x: fallbackMidpoint.x + Math.round(width * 0.18),
          y: fallbackMidpoint.y,
          box: {
            x: fallbackMidpoint.x + Math.round(width * 0.18) - halfBox,
            y: fallbackMidpoint.y - halfBox,
            width: defaultBoxSize,
            height: defaultBoxSize
          }
        },
        midpoint: fallbackMidpoint,
        confidence: 0
      };
    },

    /**
     * High-definition unsharp-mask sharpness filter.
     * Enhances eye/edge clarity without artifacts or color distortion.
     *
     * @param {Uint8ClampedArray|Uint8Array} rgba
     * @param {number} width
     * @param {number} height
     * @param {Object} [options]
     * @param {number} [options.amount=0.6] - Sharpening intensity (0 to 1.5)
     * @param {number} [options.focalX] - Normalized eye center X
     * @param {number} [options.focalY] - Normalized eye center Y
     * @param {number} [options.radius=0.4] - Normalized radius of sharpness zone
     * @returns {Uint8ClampedArray}
     */
    applySharpnessFilter(rgba, width, height, options = {}) {
      const baseAmount = options.amount !== undefined ? options.amount : 0.6;
      const output = new Uint8ClampedArray(rgba.length);

      // Copy edge pixels as-is
      output.set(rgba);

      const focalX = options.focalX;
      const focalY = options.focalY;
      const hasFocal = focalX !== undefined && focalY !== undefined;
      const maxDist = (options.radius || 0.4) * Math.min(width, height);

      for (let y = 1; y < height - 1; y++) {
        const rowOffset = y * width;
        const topOffset = (y - 1) * width;
        const btmOffset = (y + 1) * width;

        for (let x = 1; x < width - 1; x++) {
          let amount = baseAmount;
          if (hasFocal) {
            const dx = x - focalX * width;
            const dy = y - focalY * height;
            const dist = Math.sqrt(dx * dx + dy * dy);
            const weight = Math.max(0.2, 1 - dist / maxDist);
            amount = baseAmount * weight;
          }

          const centerIdx = (rowOffset + x) * 4;
          const topIdx = (topOffset + x) * 4;
          const btmIdx = (btmOffset + x) * 4;
          const leftIdx = (rowOffset + (x - 1)) * 4;
          const rightIdx = (rowOffset + (x + 1)) * 4;

          // Apply 3x3 cross unsharp kernel: [0, -a, 0 / -a, 1+4a, -a / 0, -a, 0]
          for (let c = 0; c < 3; c++) {
            const centerVal = rgba[centerIdx + c];
            const neighborSum =
              rgba[topIdx + c] +
              rgba[btmIdx + c] +
              rgba[leftIdx + c] +
              rgba[rightIdx + c];
            const sharpVal = centerVal * (1 + 4 * amount) - neighborSum * amount;
            output[centerIdx + c] = Math.max(0, Math.min(255, Math.round(sharpVal)));
          }
          output[centerIdx + 3] = rgba[centerIdx + 3]; // Preserve alpha
        }
      }

      return output;
    }
  };

  return CameraEngine;
});
