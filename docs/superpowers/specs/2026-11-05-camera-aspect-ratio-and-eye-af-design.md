# Design Specification: Camera Aspect Ratio Fix & Eye AF Engine

## 1. Intent & Why
The photo booth feature of "The Memory Circle" web application currently stretches photos when rendering them into different layout templates (such as vertical 4-cut strips, polaroids, and collages) because raw video dimensions are drawn without aspect ratio preservation. Furthermore, users want an automatic Eye Detector that places real-time bounding boxes over the subject's eyes, ensures the eyes are razor-sharp (eliminating manual focus guesswork), and frames the subject cleanly even with movement or shallow depth of field.

## 2. Goals, Non-Goals, and Anti-Goals
* **Goals:**
  * Eliminate image distortion and stretching across all layouts (`grid4x4`, `strip4`, `collage2x2`, `singlePolaroid`, `film35mm`) and all inputs (desktop webcam, Android, and iOS phone camera snaps).
  * Implement an Eye AF detection engine that tracks eyes in real-time on live video preview with green/cyan bounding boxes and an "EYE AF [LOCKED]" status.
  * Request hardware continuous autofocus on supported mobile camera tracks (`focusMode: 'continuous'`).
  * Ensure subject's eyes are razor-sharp by applying a digital sharpness/unsharp-mask enhancement on capture.
  * Frame photos intelligently using detected eye coordinates (preventing heads from being awkwardly cut off).
  * Provide an intuitive toggle in the Photo Booth Studio panel to enable or disable Eye AF.
* **Non-Goals:**
  * Heavy 3D mesh rendering or emotion classification.
  * Multi-hundred-megabyte machine learning bundles.
* **Anti-Goals:**
  * Breaking the zero external dependency constraint from `AGENTS.md`.
  * Causing UI stutter or high frame latency on low-end mobile devices.

## 3. Constraints
* **Stack:** Plain HTML5, CSS3, Vanilla JavaScript (ES6+).
* **Zero External Dependencies:** No npm, no external ML frameworks, no third-party CDN libraries.
* **Compatibility:** Must function on iOS Safari, Android Chrome, and Desktop browsers.
* **Relative Paths:** Maintain relative paths for GitHub Pages compatibility.

## 4. Approaches Considered
1. **Approach 1: Hybrid Eye AF Engine (Chosen)**
   * *Description:* Aspect-ratio preserving cover-crop algorithm (`drawImageCover`) for all layout rendering; native `window.FaceDetector` API where supported with pure Vanilla JS canvas pupil/eye contrast detector fallback; live Eye AF reticle overlay; hardware focus constraint request; eye-centered framing and digital sharpness enhancement.
   * *Trade-off:* 100% compliant with zero-dependency rule, fast, runs on all browsers.
2. **Approach 2: Lightweight CDN Vision Model (MediaPipe / face-api)**
   * *Description:* Load external deep learning weights from CDN for facial landmarks.
   * *Trade-off:* Highly detailed coordinates, but violates zero-dependency requirement and introduces heavy network payloads.
3. **Approach 3: Pure Viewfinder Simulation**
   * *Description:* Fixed static/pseudo focus brackets with center crop.
   * *Trade-off:* Zero CPU overhead, but fails to track moving subjects or detect actual eyes.

## 5. Detailed Architecture & Implementation

### A. Aspect-Ratio Cover-Crop Engine
Replace direct non-proportional `ctx.drawImage(frame, 0, 0, frame.width, frame.height, dx, dy, dw, dh)` calls with a reusable helper:
```javascript
const drawImageCover = (ctx, img, dx, dy, dw, dh, focalX = 0.5, focalY = 0.4) => {
  const imgW = img.width || img.videoWidth;
  const imgH = img.height || img.videoHeight;
  const imgRatio = imgW / imgH;
  const targetRatio = dw / dh;

  let sx, sy, sw, sh;
  if (imgRatio > targetRatio) {
    // Source image is wider than target
    sh = imgH;
    sw = imgH * targetRatio;
    sx = Math.max(0, Math.min(imgW - sw, imgW * focalX - sw / 2));
    sy = 0;
  } else {
    // Source image is taller than target
    sw = imgW;
    sh = imgW / targetRatio;
    sx = 0;
    sy = Math.max(0, Math.min(imgH - sh, imgH * focalY - sh / 2));
  }
  ctx.drawImage(img, sx, sy, sw, sh, dx, dy, dw, dh);
};
```
This guarantees zero stretching on any screen or device.

### B. Eye Detection Engine (Hybrid)
1. **Native API:** If `window.FaceDetector` is present, detect faces and extract eyes/landmarks or upper facial bounding boxes.
2. **Vanilla JS Fallback:** For browsers without native FaceDetector (e.g. iOS Safari):
   * Downscale video frame onto a hidden low-res canvas (160x120) every 80ms.
   * Run a fast luminance-gradient and contrast-valley scan in the upper half of the detected skin/face region to identify the left and right pupil coordinates.
3. **Hardware Autofocus Integration:** When starting the camera, include `{ advanced: [{ focusMode: 'continuous' }] }` in `video` constraints.

### C. Live Eye AF Viewfinder UI
* In `#camera-viewport-wrapper`, add an Eye AF overlay layer:
  * Two responsive bounding box reticles with corner brackets around the detected eyes.
  * An animated badge: `[EYE AF LOCKED]` with a soft pulsing green/cyan glow.
  * Audio chirp confirmation upon eye lock using Web Audio API oscillator.

### D. Razor-Sharp Post-Capture Processing
* When snapping the photo, apply a localized or full-frame unsharp mask (convolution kernel `[-1, -1, -1, -1, 9, -1, -1, -1, -1]`) weighted around the detected eye region so eyes and eyelashes appear crisp, sharp, and high-definition.

### E. Studio Controls
* Add an "Eye AF Focus" switch/toggle button in the booth studio controls (under Filters or Layout) so users can toggle real-time eye tracking on/off.

## 6. What's Left to the Builder
* Adding the Eye AF overlay markup in `index.html`.
* Adding CSS styling for the bounding boxes and locked badge in `style.css`.
* Integrating the `drawImageCover`, eye detector loop, and sharpness enhancer into `script.js`.
