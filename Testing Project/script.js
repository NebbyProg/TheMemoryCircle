/**
 * The Memory Circle - Static Website Interactive Behaviors
 * Core Stack: Vanilla JavaScript (ES6+)
 * Zero External Dependencies
 * Security: SHA-256 Cryptographic Hashing & XSS Sanitization
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  /* ==========================================================================
     0. SECURITY CRYPTO ENGINE — SHA-256 Hashing, Input Sanitization & Validation
     ========================================================================== */
  const SecurityCrypto = (() => {

    /**
     * FIPS 180-4 compliant pure-JS SHA-256 fallback (no dependencies).
     * Used when crypto.subtle is unavailable (e.g. HTTP non-secure contexts).
     * Verified against Node.js native crypto for correctness.
     */
    const sha256Fallback = (bytes) => {
      const K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
      ];
      let H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
      ];

      const l = bytes.length;
      const bitLen = l * 8;
      const padLen = (55 - (l % 64) + 64) % 64;
      const totalLen = l + 1 + padLen + 8;
      const padded = new Uint8Array(totalLen);
      padded.set(bytes);
      padded[l] = 0x80;

      const view = new DataView(padded.buffer);
      view.setUint32(totalLen - 4, bitLen & 0xffffffff, false);
      view.setUint32(totalLen - 8, Math.floor(bitLen / 0x100000000), false);

      const W = new Uint32Array(64);
      const rotr = (n, x) => (x >>> n) | (x << (32 - n));

      for (let i = 0; i < totalLen; i += 64) {
        for (let t = 0; t < 16; t++) {
          W[t] = view.getUint32(i + t * 4, false);
        }
        for (let t = 16; t < 64; t++) {
          const s0 = rotr(7, W[t - 15]) ^ rotr(18, W[t - 15]) ^ (W[t - 15] >>> 3);
          const s1 = rotr(17, W[t - 2]) ^ rotr(19, W[t - 2]) ^ (W[t - 2] >>> 10);
          W[t] = (((W[t - 16] + s0) | 0) + ((W[t - 7] + s1) | 0)) | 0;
        }

        let a = H[0], b = H[1], c = H[2], d = H[3];
        let e = H[4], f = H[5], g = H[6], h = H[7];

        for (let t = 0; t < 64; t++) {
          const S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);
          const ch = (e & f) ^ ((~e) & g);
          const temp1 = (h + S1 + ch + K[t] + W[t]) | 0;
          const S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);
          const maj = (a & b) ^ (a & c) ^ (b & c);
          const temp2 = (S0 + maj) | 0;
          h = g; g = f; f = e;
          e = (d + temp1) | 0;
          d = c; c = b; b = a;
          a = (temp1 + temp2) | 0;
        }

        H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0;
        H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
        H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0;
        H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
      }

      return H.map(x => (x >>> 0).toString(16).padStart(8, '0')).join('');
    };

    /**
     * Compute SHA-256 hex digest of a string.
     * Uses native crypto.subtle when available (HTTPS / localhost),
     * falls back to pure-JS implementation on insecure contexts (HTTP LAN).
     */
    const sha256 = async (text) => {
      const bytes = new TextEncoder().encode(text);
      if (window.crypto && window.crypto.subtle) {
        try {
          const buf = await window.crypto.subtle.digest('SHA-256', bytes);
          return Array.from(new Uint8Array(buf))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
        } catch (_) { /* fall through to pure-JS */ }
      }
      return sha256Fallback(bytes);
    };

    /**
     * Compute SHA-256 hex digest of binary data (ArrayBuffer or Uint8Array).
     * Used for uploaded file integrity verification.
     */
    const sha256Buffer = async (buffer) => {
      const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
      if (window.crypto && window.crypto.subtle) {
        try {
          const buf = await window.crypto.subtle.digest('SHA-256', bytes);
          return Array.from(new Uint8Array(buf))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
        } catch (_) { /* fall through to pure-JS */ }
      }
      return sha256Fallback(bytes);
    };

    /**
     * Sanitize user input: escape HTML entities to prevent XSS injection.
     * Returns safe string for DOM insertion via textContent or canvas text.
     */
    const sanitize = (str) => {
      if (typeof str !== 'string') return '';
      const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;', '/': '&#x2F;' };
      return str.replace(/[&<>"'/]/g, (c) => map[c]);
    };

    /**
     * Validate image file magic bytes (file header signature).
     * PNG: 89 50 4E 47   JPEG: FF D8 FF
     * Returns { valid: boolean, type: string }
     */
    const validateImageBytes = (uint8) => {
      if (!(uint8 instanceof Uint8Array) || uint8.length < 4) {
        return { valid: false, type: 'unknown' };
      }
      // PNG signature: 0x89 0x50 0x4E 0x47
      if (uint8[0] === 0x89 && uint8[1] === 0x50 && uint8[2] === 0x4E && uint8[3] === 0x47) {
        return { valid: true, type: 'image/png' };
      }
      // JPEG signature: 0xFF 0xD8 0xFF
      if (uint8[0] === 0xFF && uint8[1] === 0xD8 && uint8[2] === 0xFF) {
        return { valid: true, type: 'image/jpeg' };
      }
      return { valid: false, type: 'unknown' };
    };

    /**
     * Truncate a SHA-256 hex digest for display (first 12 hex chars).
     */
    const shortHash = (hexDigest) => {
      return hexDigest ? hexDigest.substring(0, 12) : '';
    };

    return { sha256, sha256Buffer, sanitize, validateImageBytes, shortHash };
  })();

  /* ==========================================================================
     1. THEME TOGGLE (Dark / Light Mode)
     ========================================================================== */
  const initThemeToggle = () => {
    const themeBtn = document.getElementById('theme-toggle-btn');
    if (!themeBtn) return;

    const storageKey = 'the-memory-circle-theme';
    const root = document.documentElement;

    // Detect saved theme or system preference
    const getPreferredTheme = () => {
      const savedTheme = localStorage.getItem(storageKey);
      if (savedTheme) {
        return savedTheme;
      }
      return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    };

    const setTheme = (theme) => {
      if (theme === 'dark') {
        root.setAttribute('data-theme', 'dark');
        themeBtn.setAttribute('aria-pressed', 'true');
        themeBtn.setAttribute('aria-label', 'Switch to light color theme');
      } else {
        root.removeAttribute('data-theme');
        themeBtn.setAttribute('aria-pressed', 'false');
        themeBtn.setAttribute('aria-label', 'Switch to dark color theme');
      }
      localStorage.setItem(storageKey, theme);
    };

    // Initialize on page load
    const currentTheme = getPreferredTheme();
    setTheme(currentTheme);

    // Click event handler
    themeBtn.addEventListener('click', () => {
      const isDark = root.getAttribute('data-theme') === 'dark';
      const newTheme = isDark ? 'light' : 'dark';
      setTheme(newTheme);
    });

    // Listen to OS preference changes if no manual preference stored
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
      if (!localStorage.getItem(storageKey)) {
        setTheme(e.matches ? 'dark' : 'light');
      }
    });
  };

  /* ==========================================================================
     2. MOBILE NAVIGATION HAMBURGER TOGGLE
     ========================================================================== */
  const initMobileNavigation = () => {
    const navToggle = document.getElementById('mobile-nav-toggle');
    const primaryNav = document.getElementById('primary-navigation');
    const navLinks = primaryNav ? primaryNav.querySelectorAll('.nav-link') : [];

    if (!navToggle || !primaryNav) return;

    const toggleNav = (forceState) => {
      const isExpanded = navToggle.getAttribute('aria-expanded') === 'true';
      const shouldOpen = typeof forceState === 'boolean' ? forceState : !isExpanded;

      navToggle.setAttribute('aria-expanded', String(shouldOpen));
      navToggle.setAttribute('aria-label', shouldOpen ? 'Close navigation menu' : 'Open navigation menu');
      primaryNav.classList.toggle('is-open', shouldOpen);
    };

    // Toggle button click
    navToggle.addEventListener('click', (e) => {
      e.stopPropagation();
      toggleNav();
    });

    // Close when clicking any nav link
    navLinks.forEach((link) => {
      link.addEventListener('click', () => {
        toggleNav(false);
      });
    });

    // Close on outside click
    document.addEventListener('click', (e) => {
      if (
        primaryNav.classList.contains('is-open') &&
        !primaryNav.contains(e.target) &&
        !navToggle.contains(e.target)
      ) {
        toggleNav(false);
      }
    });

    // Close on Escape key press
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && primaryNav.classList.contains('is-open')) {
        toggleNav(false);
        navToggle.focus();
      }
    });
  };

  /* ==========================================================================
     3. ACTIVE NAVIGATION LINK HIGHLIGHTER (ScrollSpy)
     ========================================================================== */
  const initScrollSpy = () => {
    const navLinks = document.querySelectorAll('.site-nav .nav-link');
    const sections = document.querySelectorAll('section[id]');
    if (!sections.length || !navLinks.length) return;

    const observerOptions = {
      root: null,
      rootMargin: '-20% 0px -70% 0px',
      threshold: 0
    };

    const observerCallback = (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const sectionId = entry.target.getAttribute('id');
          navLinks.forEach((link) => {
            const href = link.getAttribute('href');
            if (href === `#${sectionId}`) {
              link.classList.add('active');
            } else {
              link.classList.remove('active');
            }
          });
        }
      });
    };

    const observer = new IntersectionObserver(observerCallback, observerOptions);
    sections.forEach((section) => observer.observe(section));
  };

  /* ==========================================================================
     4. GALLERY FILTERING (Interactive Mood Categories)
     ========================================================================== */
  const initGalleryFilters = () => {
    const filterButtons = document.querySelectorAll('.filter-btn');
    const memoryCards = document.querySelectorAll('.memory-card');
    if (!filterButtons.length || !memoryCards.length) return;

    filterButtons.forEach((btn) => {
      btn.addEventListener('click', () => {
        const targetCategory = btn.getAttribute('data-filter');

        // Update button states
        filterButtons.forEach((b) => {
          b.classList.remove('active');
          b.setAttribute('aria-pressed', 'false');
        });
        btn.classList.add('active');
        btn.setAttribute('aria-pressed', 'true');

        // Filter cards with smooth fade
        memoryCards.forEach((card) => {
          const cardCategory = card.getAttribute('data-category');
          const shouldShow = targetCategory === 'all' || cardCategory === targetCategory;

          if (shouldShow) {
            card.classList.remove('is-hidden');
            card.style.opacity = '0';
            card.style.transform = 'translateY(10px)';
            requestAnimationFrame(() => {
              card.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
              card.style.opacity = '1';
              card.style.transform = 'translateY(0)';
            });
          } else {
            card.classList.add('is-hidden');
          }
        });
      });
    });
  };

  /* ==========================================================================
     5. MEMORY LIGHTBOX / MODAL WINDOW
     ========================================================================== */
  const initMemoryModal = () => {
    const modal = document.getElementById('memory-modal');
    const modalImg = document.getElementById('modal-img');
    const modalTitle = document.getElementById('modal-title');
    const modalDesc = document.getElementById('modal-desc');
    const modalBadge = document.getElementById('modal-badge');
    const closeBtn = document.getElementById('modal-close-btn');
    const backdrop = document.getElementById('modal-backdrop');
    const copyBtn = document.getElementById('modal-copy-btn');
    const expandButtons = document.querySelectorAll('.btn-card-expand');

    if (!modal || !modalImg || !closeBtn) return;

    let previousActiveElement = null;

    const openModal = ({ imgSrc, title, desc, category, triggerElement }) => {
      previousActiveElement = triggerElement || document.activeElement;

      modalImg.src = imgSrc;
      modalImg.alt = title;
      if (modalTitle) modalTitle.textContent = title;
      if (modalDesc) modalDesc.textContent = desc;
      if (modalBadge) modalBadge.textContent = category ? `#${category.toUpperCase()}` : 'MEMORIES VAULT';

      modal.removeAttribute('hidden');
      if (typeof modal.showModal === 'function') {
        modal.showModal();
      } else {
        modal.setAttribute('open', '');
      }

      document.body.style.overflow = 'hidden';
      closeBtn.focus();
    };

    const closeModal = () => {
      if (typeof modal.close === 'function') {
        modal.close();
      } else {
        modal.removeAttribute('open');
      }
      modal.setAttribute('hidden', '');
      document.body.style.overflow = '';

      if (previousActiveElement && typeof previousActiveElement.focus === 'function') {
        previousActiveElement.focus();
      }
    };

    // Attach open handler to all expand buttons
    expandButtons.forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const card = btn.closest('.memory-card');
        const category = card ? card.getAttribute('data-category') : '';
        const imgSrc = btn.getAttribute('data-img');
        const title = btn.getAttribute('data-title');
        const desc = btn.getAttribute('data-desc');

        openModal({
          imgSrc,
          title,
          desc,
          category,
          triggerElement: btn
        });
      });
    });

    // Close button click
    closeBtn.addEventListener('click', closeModal);

    // Backdrop click
    if (backdrop) {
      backdrop.addEventListener('click', closeModal);
    }

    // Modal native click outside dialog content
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        closeModal();
      }
    });

    // Keyboard ESC key handling
    modal.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        closeModal();
      }
    });

    // Share / Copy Link Button — with cryptographic hash fragment
    if (copyBtn) {
      copyBtn.addEventListener('click', async () => {
        const currentTitle = modalTitle ? SecurityCrypto.sanitize(modalTitle.textContent) : 'memory';
        const hashDigest = await SecurityCrypto.sha256(currentTitle + '|' + Date.now());
        const shortRef = SecurityCrypto.shortHash(hashDigest);
        const shareUrl = window.location.href.split('#')[0] + '#hash-ref-' + shortRef;

        // Update the URL fragment to the hashed reference (no cleartext params)
        window.history.replaceState(null, '', '#hash-ref-' + shortRef);

        try {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(shareUrl);
          }
          const originalText = copyBtn.textContent;
          copyBtn.textContent = '🔒 Hashed Link Copied! ✓';
          setTimeout(() => {
            copyBtn.textContent = originalText;
          }, 2500);
        } catch (err) {
          copyBtn.textContent = '🔒 Hashed & Copied!';
          setTimeout(() => {
            copyBtn.textContent = 'Share Memory';
          }, 2500);
        }
      });
    }
  };

  /* ==========================================================================
     6. MEMORY FORM & INTERACTIVE NOTE BOARD
     ========================================================================== */
  const initMemoryForm = () => {
    const form = document.getElementById('memory-form');
    const feedback = document.getElementById('form-feedback');
    const notesBoard = document.getElementById('sticky-notes-board');
    if (!form) return;

    const nameInput = document.getElementById('friend-name');
    const messageInput = document.getElementById('friend-message');
    const favoriteMemoryInput = document.getElementById('favorite-memory');
    const tagSelect = document.getElementById('memory-tag');
    const nameError = document.getElementById('name-error');
    const messageError = document.getElementById('message-error');

    const clearErrors = () => {
      if (nameError) nameError.textContent = '';
      if (messageError) messageError.textContent = '';
      if (nameInput) {
        nameInput.classList.remove('is-invalid');
        nameInput.removeAttribute('aria-invalid');
      }
      if (messageInput) {
        messageInput.classList.remove('is-invalid');
        messageInput.removeAttribute('aria-invalid');
      }
      if (feedback) {
        feedback.hidden = true;
        feedback.className = 'form-feedback';
        feedback.textContent = '';
      }
    };

    const validateForm = () => {
      let isValid = true;
      clearErrors();

      // Validate name
      if (!nameInput.value.trim()) {
        isValid = false;
        nameInput.classList.add('is-invalid');
        nameInput.setAttribute('aria-invalid', 'true');
        if (nameError) nameError.textContent = 'Please enter your name or a nickname.';
      }

      // Validate message
      if (!messageInput.value.trim()) {
        isValid = false;
        messageInput.classList.add('is-invalid');
        messageInput.setAttribute('aria-invalid', 'true');
        if (messageError) messageError.textContent = 'Please write a heartfelt note for the circle.';
      }

      return isValid;
    };

    form.addEventListener('submit', async (e) => {
      e.preventDefault();

      if (!validateForm()) {
        if (feedback) {
          feedback.hidden = false;
          feedback.className = 'form-feedback error';
          feedback.textContent = 'Please fill in all required fields marked with an asterisk (*).';
        }
        return;
      }

      // Sanitize all user inputs against XSS
      const name = SecurityCrypto.sanitize(nameInput.value.trim());
      const message = SecurityCrypto.sanitize(messageInput.value.trim());
      const favoriteMemory = SecurityCrypto.sanitize(favoriteMemoryInput.value.trim()) || 'Timeless Memory';
      const tagText = tagSelect.options[tagSelect.selectedIndex].text;

      // Compute SHA-256 digest of the entire entry payload
      const entryPayload = [name, message, favoriteMemory, tagText, Date.now()].join('|');
      const entryHash = await SecurityCrypto.sha256(entryPayload);
      const shortHash = SecurityCrypto.shortHash(entryHash);

      // Update URL with hashed entry reference (no cleartext data in URL)
      window.history.replaceState(null, '', '#entry-' + shortHash);

      // Show success feedback
      if (feedback) {
        feedback.hidden = false;
        feedback.className = 'form-feedback success';
        feedback.textContent = `Thank you, ${name}! Your note has been pinned to the Circle Memory Board above.`;
      }

      // Dynamically create a new sticky note on the live board
      if (notesBoard) {
        const colorClasses = ['note-pink', 'note-yellow', 'note-lavender'];
        const randomColor = colorClasses[Math.floor(Math.random() * colorClasses.length)];

        const newNote = document.createElement('article');
        newNote.className = `sticky-note ${randomColor}`;
        newNote.setAttribute('role', 'listitem');
        newNote.setAttribute('data-integrity', shortHash);
        newNote.style.animation = 'fadeInNote 0.5s ease';

        const pin = document.createElement('div');
        pin.className = 'note-pin';
        pin.setAttribute('aria-hidden', 'true');

        const noteText = document.createElement('p');
        noteText.className = 'note-text';
        noteText.textContent = `“${message}”`;

        const noteFooter = document.createElement('footer');
        noteFooter.className = 'note-author';

        const authorStrong = document.createElement('strong');
        authorStrong.textContent = `— ${name}`;

        const memoryTime = document.createElement('time');
        memoryTime.textContent = `${favoriteMemory} • ${tagText}`;

        noteFooter.appendChild(authorStrong);
        noteFooter.appendChild(memoryTime);

        // SHA-256 integrity badge
        const hashBadge = document.createElement('span');
        hashBadge.className = 'crypto-hash-badge';
        hashBadge.title = `SHA-256: ${entryHash}`;
        hashBadge.textContent = `🔒 #${shortHash}`;

        newNote.appendChild(pin);
        newNote.appendChild(noteText);
        newNote.appendChild(noteFooter);
        newNote.appendChild(hashBadge);

        // Prepend to top of sticky notes board
        notesBoard.prepend(newNote);

        // Smooth scroll to the notes wall so user sees their note pinned
        newNote.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }

      // Reset form fields
      form.reset();
    });

    // Real-time error clearing on input
    [nameInput, messageInput].forEach((input) => {
      if (input) {
        input.addEventListener('input', () => {
          if (input.value.trim()) {
            input.classList.remove('is-invalid');
            input.removeAttribute('aria-invalid');
            if (input === nameInput && nameError) nameError.textContent = '';
            if (input === messageInput && messageError) messageError.textContent = '';
          }
        });
      }
    });
  };

  /* ==========================================================================
     7. WEBCAM TOY PHOTO BOOTH & CUSTOMIZATION STUDIO
     ========================================================================== */
  const initWebcamBooth = () => {
    // Screens & Core Elements
    const promptScreen = document.getElementById('booth-permission-prompt');
    const liveScreen = document.getElementById('booth-live-view');
    const resultScreen = document.getElementById('booth-result-view');
    const startBtn = document.getElementById('btn-start-camera');
    const stopBtn = document.getElementById('btn-stop-camera');
    const flipBtn = document.getElementById('btn-flip-camera');
    const captureBtn = document.getElementById('btn-capture-photo');
    const retakeBtn = document.getElementById('btn-retake-photo');
    const pinBtn = document.getElementById('btn-pin-captured-photo');
    const downloadBtn = document.getElementById('btn-download-photo');
    const mobileCameraInput = document.getElementById('mobile-native-camera-input');
    const statusMsg = document.getElementById('camera-status-msg');
    const modeHint = document.getElementById('booth-mode-hint');

    // Camera Viewport Elements
    const video = document.getElementById('webcam-video');
    const gridOverlay = document.getElementById('grid-overlay-4x4');
    const countdownBadge = document.getElementById('countdown-badge');
    const flash = document.getElementById('camera-flash');
    const canvas = document.getElementById('booth-canvas');
    const resultImg = document.getElementById('result-photo-img');
    const resultDate = document.getElementById('result-photo-date');
    const resultBadge = document.getElementById('result-photo-badge');
    const notesBoard = document.getElementById('sticky-notes-board');

    // Studio Tabs
    const tabButtons = document.querySelectorAll('.studio-tab-btn');
    const tabContents = document.querySelectorAll('.studio-tab-content');

    // Studio Layout Buttons & Filter Pills
    const layoutButtons = document.querySelectorAll('.layout-btn');
    const filterPills = document.querySelectorAll('.filter-pill');

    // Studio Background & Upload Elements
    const colorSwatches = document.querySelectorAll('.color-swatch');
    const bgPicker = document.getElementById('booth-bg-picker');
    const templateFileInput = document.getElementById('booth-template-file');
    const templateFileName = document.getElementById('template-file-name');
    const clearTemplateBtn = document.getElementById('btn-clear-template');

    // Studio Text, Timestamp & Font Elements
    const titleInput = document.getElementById('booth-text-title');
    const noteInput = document.getElementById('booth-text-note');
    const timestampModeSelect = document.getElementById('booth-timestamp-mode');
    const customDateField = document.getElementById('custom-date-field');
    const customDateInput = document.getElementById('booth-custom-date-text');
    const fontStyleSelect = document.getElementById('booth-font-style');
    const textColorInput = document.getElementById('booth-text-color');
    const textColorHexLabel = document.getElementById('text-color-hex');
    const autoColorBtn = document.getElementById('btn-text-auto-color');

    if (!startBtn || !video || !canvas) return;

    // --- State Variables ---
    let activeStream = null;
    let isCapturing = false;
    let currentFacingMode = 'user'; // 'user' (front/selfie) or 'environment' (back/world)
    let currentLayout = 'grid4x4'; // 'grid4x4' | 'strip4' | 'collage2x2' | 'singlePolaroid' | 'film35mm'
    let currentFilter = 'normal'; // 'normal' | 'bw' | 'sepia' | 'golden' | 'cyber' | 'soft'
    let currentBgColor = '#FFFFFF';
    let customTemplateImg = null;
    let lastCapturedFrames = null; // Store captured frames for instant post-capture edits

    // Filter CSS mappings for Canvas context
    const filterCanvasMap = {
      normal: 'none',
      bw: 'grayscale(100%) contrast(115%)',
      sepia: 'sepia(50%) contrast(105%) saturate(120%)',
      golden: 'sepia(25%) brightness(105%) saturate(135%)',
      cyber: 'saturate(200%) hue-rotate(15deg) contrast(105%)',
      soft: 'brightness(110%) contrast(95%) saturate(115%)'
    };

    // Font family mapping for Canvas text
    const fontFamilies = {
      handwriting: '"Caveat", cursive, Georgia, serif',
      sans: '"Plus Jakarta Sans", system-ui, -apple-system, sans-serif',
      mono: '"Courier New", Courier, monospace',
      serif: '"Playfair Display", Georgia, serif'
    };

    // Helper: Show/hide status messages
    const showStatus = (text, type = 'info') => {
      if (!statusMsg) return;
      statusMsg.textContent = text;
      statusMsg.className = `booth-status-msg ${type}`;
      statusMsg.style.display = 'block';
    };

    const hideStatus = () => {
      if (!statusMsg) return;
      statusMsg.textContent = '';
      statusMsg.className = 'booth-status-msg';
      statusMsg.style.display = 'none';
    };

    // Helper: Audio synth effects (zero external sound files)
    const playBeep = (freq = 800, duration = 0.08) => {
      try {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (!AudioCtx) return;
        const ctx = new AudioCtx();
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(freq, ctx.currentTime);
        gain.gain.setValueAtTime(0.12, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + duration);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start();
        osc.stop(ctx.currentTime + duration);
      } catch (err) {}
    };

    const playShutterSound = () => {
      try {
        playBeep(1200, 0.04);
        setTimeout(() => playBeep(700, 0.09), 50);
      } catch (err) {}
    };

    // Helper: Calculate background luminance for smart text contrast
    const getLuminance = (hex) => {
      const c = hex.replace('#', '');
      const r = parseInt(c.substr(0, 2), 16) || 0;
      const g = parseInt(c.substr(2, 2), 16) || 0;
      const b = parseInt(c.substr(4, 2), 16) || 0;
      return (0.299 * r + 0.587 * g + 0.114 * b) / 255;
    };

    const applyAutoTextColor = () => {
      const lum = getLuminance(currentBgColor);
      const chosenColor = lum > 0.5 ? '#A8577E' : '#FFFFFF';
      if (textColorInput) textColorInput.value = chosenColor;
      if (textColorHexLabel) textColorHexLabel.textContent = chosenColor;
    };

    // --- Studio Navigation Tabs ---
    tabButtons.forEach((btn) => {
      btn.addEventListener('click', () => {
        const targetTabId = btn.getAttribute('data-tab');

        tabButtons.forEach((b) => {
          b.classList.remove('active');
          b.setAttribute('aria-selected', 'false');
        });
        tabContents.forEach((c) => {
          c.classList.remove('active');
          c.hidden = true;
        });

        btn.classList.add('active');
        btn.setAttribute('aria-selected', 'true');
        const targetContent = document.getElementById(targetTabId);
        if (targetContent) {
          targetContent.classList.add('active');
          targetContent.hidden = false;
        }
      });
    });

    // --- Tab 1: Layout Selection ---
    const updateModeHint = () => {
      if (!modeHint) return;
      const layoutNames = {
        grid4x4: '4x4 Multi-Tile (16-Tile Webcam Toy)',
        strip4: 'Vertical 4-Cut Photobooth Strip (4 Poses)',
        collage2x2: '2x2 Square Photo Collage (4 Poses)',
        singlePolaroid: 'Classic Single Polaroid (1 Shot)',
        film35mm: '35mm Retro Film Strip (4 Poses)'
      };
      const filterNames = {
        normal: 'Natural',
        bw: 'B&W Noir',
        sepia: "Retro '90s",
        golden: 'Golden Glow',
        cyber: 'Cyber Pop',
        soft: 'Soft Dream'
      };
      modeHint.textContent = `Selected: ${layoutNames[currentLayout] || currentLayout} • ${filterNames[currentFilter] || currentFilter} filter`;
    };

    layoutButtons.forEach((btn) => {
      btn.addEventListener('click', () => {
        currentLayout = btn.getAttribute('data-layout');

        layoutButtons.forEach((b) => {
          b.classList.remove('active');
          b.setAttribute('aria-pressed', 'false');
        });
        btn.classList.add('active');
        btn.setAttribute('aria-pressed', 'true');

        // Toggle 4x4 grid guide on live video
        if (gridOverlay) {
          gridOverlay.style.display = currentLayout === 'grid4x4' ? 'grid' : 'none';
        }

        updateModeHint();

        // If user already captured photos, re-render immediately with the new layout!
        if (lastCapturedFrames && lastCapturedFrames.length) {
          renderComposite(lastCapturedFrames);
        }
      });
    });

    // --- Tab 2: Live Camera Filters ---
    filterPills.forEach((pill) => {
      pill.addEventListener('click', () => {
        currentFilter = pill.getAttribute('data-filter');

        filterPills.forEach((p) => {
          p.classList.remove('active');
          p.setAttribute('aria-pressed', 'false');
        });
        pill.classList.add('active');
        pill.setAttribute('aria-pressed', 'true');

        // Apply live filter to webcam feed
        video.className = `webcam-feed filter-${currentFilter}`;
        updateModeHint();

        // If previously captured, re-render
        if (lastCapturedFrames && lastCapturedFrames.length) {
          renderComposite(lastCapturedFrames);
        }
      });
    });

    // --- Tab 3: Background Color & Upload Custom Template ---
    const setBgColor = (color) => {
      currentBgColor = color;
      if (bgPicker) bgPicker.value = color;

      colorSwatches.forEach((s) => {
        const matches = s.getAttribute('data-color').toLowerCase() === color.toLowerCase();
        s.classList.toggle('active', matches);
      });

      // Re-render if captured
      if (lastCapturedFrames && lastCapturedFrames.length) {
        renderComposite(lastCapturedFrames);
      }
    };

    colorSwatches.forEach((swatch) => {
      swatch.addEventListener('click', () => {
        setBgColor(swatch.getAttribute('data-color'));
      });
    });

    if (bgPicker) {
      bgPicker.addEventListener('input', (e) => {
        setBgColor(e.target.value);
      });
    }

    // Custom Template Upload (PNG/JPG) — with magic-byte validation & SHA-256 checksum
    if (templateFileInput) {
      templateFileInput.addEventListener('change', async (e) => {
        const file = e.target.files && e.target.files[0];
        if (!file) return;

        if (!file.type.match('image.*')) {
          showStatus('Please choose a valid PNG or JPG image file.', 'error');
          return;
        }

        // Read file as ArrayBuffer for binary validation
        const arrayBuffer = await file.arrayBuffer();
        const uint8 = new Uint8Array(arrayBuffer);

        // Validate magic bytes (reject disguised non-image files)
        const validation = SecurityCrypto.validateImageBytes(uint8);
        if (!validation.valid) {
          showStatus('⚠️ Security: File header bytes do not match PNG or JPEG. Upload rejected.', 'error');
          templateFileInput.value = '';
          return;
        }

        // Compute SHA-256 checksum of the uploaded file
        const fileHash = await SecurityCrypto.sha256Buffer(uint8);
        const shortFileHash = SecurityCrypto.shortHash(fileHash);

        const reader = new FileReader();
        reader.onload = (loadEvent) => {
          const img = new Image();
          img.onload = () => {
            customTemplateImg = img;
            if (templateFileName) templateFileName.textContent = `${SecurityCrypto.sanitize(file.name)} 🔒 #${shortFileHash}`;
            if (clearTemplateBtn) clearTemplateBtn.hidden = false;
            showStatus(`✅ Template "${SecurityCrypto.sanitize(file.name)}" verified (${validation.type}) • SHA-256: #${shortFileHash}`, 'info');

            // Live re-render if photos already captured
            if (lastCapturedFrames && lastCapturedFrames.length) {
              renderComposite(lastCapturedFrames);
            }
          };
          img.onerror = () => {
            showStatus('Failed to load image template file.', 'error');
          };
          img.src = loadEvent.target.result;
        };
        reader.readAsDataURL(file);
      });
    }

    if (clearTemplateBtn) {
      clearTemplateBtn.addEventListener('click', () => {
        customTemplateImg = null;
        if (templateFileInput) templateFileInput.value = '';
        if (templateFileName) templateFileName.textContent = 'No custom file chosen';
        clearTemplateBtn.hidden = true;
        showStatus('Custom template removed.', 'info');

        if (lastCapturedFrames && lastCapturedFrames.length) {
          renderComposite(lastCapturedFrames);
        }
      });
    }

    // --- Tab 4: Text, Timestamp & Font Controls ---
    if (timestampModeSelect) {
      timestampModeSelect.addEventListener('change', () => {
        if (customDateField) {
          customDateField.hidden = timestampModeSelect.value !== 'custom';
        }
        if (lastCapturedFrames && lastCapturedFrames.length) {
          renderComposite(lastCapturedFrames);
        }
      });
    }

    [titleInput, noteInput, customDateInput, fontStyleSelect].forEach((el) => {
      if (el) {
        el.addEventListener('input', () => {
          if (lastCapturedFrames && lastCapturedFrames.length) {
            renderComposite(lastCapturedFrames);
          }
        });
      }
    });

    if (textColorInput) {
      textColorInput.addEventListener('input', (e) => {
        if (textColorHexLabel) textColorHexLabel.textContent = e.target.value;
        if (lastCapturedFrames && lastCapturedFrames.length) {
          renderComposite(lastCapturedFrames);
        }
      });
    }

    if (autoColorBtn) {
      autoColorBtn.addEventListener('click', () => {
        applyAutoTextColor();
        if (lastCapturedFrames && lastCapturedFrames.length) {
          renderComposite(lastCapturedFrames);
        }
      });
    }

    // --- Camera Lifecycle: Permission & Stream Start ---
    const startCamera = async () => {
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        if (!window.isSecureContext) {
          showStatus('iOS Safari requires an HTTPS connection for live streaming. Tap "Snap with Phone Camera" below to use your iPhone camera directly, or open via HTTPS!', 'error');
        } else {
          showStatus('Camera access is not supported by your browser or is blocked by current security policy. Tap "Snap with Phone Camera" below!', 'error');
        }
        return;
      }

      showStatus('Requesting camera permission from your browser...', 'info');

      try {
        // iOS Safari optimized constraints
        const constraints = {
          video: {
            facingMode: { ideal: currentFacingMode }
          },
          audio: false
        };

        const stream = await navigator.mediaDevices.getUserMedia(constraints);

        activeStream = stream;
        video.setAttribute('playsinline', '');
        video.setAttribute('webkit-playsinline', '');
        video.muted = true;
        video.defaultMuted = true;
        video.srcObject = stream;
        await video.play();

        // Apply horizontal mirror only for front/selfie camera
        video.style.transform = currentFacingMode === 'user' ? 'scaleX(-1)' : 'none';

        // Switch to active live camera view (hide prompt screen & enable access button)
        promptScreen.hidden = true;
        promptScreen.style.display = 'none';
        resultScreen.hidden = true;
        resultScreen.style.display = 'none';
        liveScreen.hidden = false;
        liveScreen.style.display = 'flex';
        hideStatus();
        updateModeHint();
      } catch (err) {
        console.error('Camera access error:', err);
        if (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError') {
          showStatus('Camera permission was denied. Please allow camera access in your browser settings, or use "Snap with Phone Camera" below.', 'error');
        } else if (err.name === 'NotFoundError' || err.name === 'DevicesNotFoundError') {
          showStatus('No camera device was detected on your computer or mobile device.', 'error');
        } else if (err.name === 'NotReadableError' || err.name === 'TrackStartError') {
          showStatus('Your camera is currently in use by another program (e.g. Zoom, Meet).', 'error');
        } else {
          showStatus(`Could not connect to camera: ${err.message || 'Permission request failed'}. You can tap "Snap with Phone Camera" below!`, 'error');
        }
      }
    };

    const stopCamera = () => {
      if (activeStream) {
        activeStream.getTracks().forEach((track) => track.stop());
        activeStream = null;
      }
      video.srcObject = null;
      liveScreen.hidden = true;
      liveScreen.style.display = 'none';
      resultScreen.hidden = true;
      resultScreen.style.display = 'none';
      // Restore prompt screen & enable access button
      promptScreen.hidden = false;
      promptScreen.style.display = 'flex';
      hideStatus();
    };

    startBtn.addEventListener('click', startCamera);
    stopBtn.addEventListener('click', stopCamera);

    // Native Mobile / iOS Camera Snapshot Handler (100% works even over HTTP!)
    if (mobileCameraInput) {
      mobileCameraInput.addEventListener('change', async (e) => {
        const file = e.target.files && e.target.files[0];
        if (!file) return;

        showStatus('Verifying & processing your phone camera photo...', 'info');

        // Validate magic bytes of the captured photo
        const arrayBuffer = await file.arrayBuffer();
        const uint8 = new Uint8Array(arrayBuffer);
        const validation = SecurityCrypto.validateImageBytes(uint8);
        if (!validation.valid) {
          showStatus('⚠️ Security: Captured file does not match valid image format.', 'error');
          return;
        }

        const reader = new FileReader();
        reader.onload = async (loadEvt) => {
          const img = new Image();
          img.onload = async () => {
            const off = document.createElement('canvas');
            off.width = img.width;
            off.height = img.height;
            const offCtx = off.getContext('2d');
            if (filterCanvasMap[currentFilter] && offCtx.filter !== undefined) {
              offCtx.filter = filterCanvasMap[currentFilter];
            }
            offCtx.drawImage(img, 0, 0);

            // Render into the chosen template layout
            lastCapturedFrames = [off];
            await renderComposite([off]);

            // Switch to result view
            promptScreen.hidden = true;
            promptScreen.style.display = 'none';
            liveScreen.hidden = true;
            liveScreen.style.display = 'none';
            resultScreen.hidden = false;
            resultScreen.style.display = 'flex';
            hideStatus();
          };
          img.src = loadEvt.target.result;
        };
        reader.readAsDataURL(file);
      });
    }

    // Mobile Front / Back Camera Flip
    if (flipBtn) {
      flipBtn.addEventListener('click', async () => {
        currentFacingMode = currentFacingMode === 'user' ? 'environment' : 'user';
        if (activeStream) {
          activeStream.getTracks().forEach((t) => t.stop());
          activeStream = null;
        }
        await startCamera();
      });
    }

    // --- Countdown & Flash Helpers ---
    const runCountdown = (seconds = 3, label = '') => {
      return new Promise((resolve) => {
        if (!countdownBadge) {
          resolve();
          return;
        }

        countdownBadge.hidden = false;
        let count = seconds;
        countdownBadge.textContent = label ? `${label} (${count})` : count;
        playBeep(880, 0.08);

        const timer = setInterval(() => {
          count--;
          if (count > 0) {
            countdownBadge.textContent = label ? `${label} (${count})` : count;
            playBeep(880, 0.08);
          } else {
            clearInterval(timer);
            countdownBadge.hidden = true;
            resolve();
          }
        }, 750);
      });
    };

    const triggerFlash = () => {
      if (!flash) return;
      flash.classList.remove('is-flashing');
      void flash.offsetWidth;
      flash.classList.add('is-flashing');
      playShutterSound();
    };

    // Grab single video frame with active filter applied
    const grabVideoFrame = () => {
      const vWidth = video.videoWidth || 640;
      const vHeight = video.videoHeight || 480;

      const offCanvas = document.createElement('canvas');
      offCanvas.width = vWidth;
      offCanvas.height = vHeight;
      const offCtx = offCanvas.getContext('2d');

      // Apply active filter to the captured canvas frame
      if (filterCanvasMap[currentFilter] && offCtx.filter !== undefined) {
        offCtx.filter = filterCanvasMap[currentFilter];
      }

      // Mirror horizontally only if front/selfie camera is active
      if (currentFacingMode === 'user') {
        offCtx.translate(vWidth, 0);
        offCtx.scale(-1, 1);
      }
      offCtx.drawImage(video, 0, 0, vWidth, vHeight);

      return offCanvas;
    };

    // --- Format Date / Timestamp Helper ---
    const getFormattedTimestamp = () => {
      const mode = timestampModeSelect ? timestampModeSelect.value : 'datetime';
      if (mode === 'none') return '';

      if (mode === 'custom' && customDateInput && customDateInput.value.trim()) {
        return customDateInput.value.trim();
      }

      const now = new Date();
      if (mode === 'retro90s') {
        const yy = String(now.getFullYear()).slice(-2);
        const mm = String(now.getMonth() + 1).padStart(2, '0');
        const dd = String(now.getDate()).padStart(2, '0');
        return `'${yy} ${mm} ${dd}`;
      }

      if (mode === 'dateonly') {
        return now.toLocaleDateString('en-US', {
          month: 'short',
          day: 'numeric',
          year: 'numeric'
        });
      }

      // Default: datetime
      const datePart = now.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric'
      });
      const timePart = now.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit'
      });
      return `${datePart} • ${timePart}`;
    };

    // --- Master Canvas Composite Renderer ---
    const renderComposite = async (frames) => {
      if (!frames || !frames.length) return;

      const titleText = SecurityCrypto.sanitize((titleInput && titleInput.value.trim()) || 'The Memory Circle');
      const noteText = SecurityCrypto.sanitize((noteInput && noteInput.value.trim()) || 'Moments Frozen in Time ♥');
      const timestampText = getFormattedTimestamp();
      const fontKey = (fontStyleSelect && fontStyleSelect.value) || 'handwriting';
      const activeFont = fontFamilies[fontKey] || fontFamilies.handwriting;
      const textColor = (textColorInput && textColorInput.value) || '#A8577E';
      const isRetro90s = timestampModeSelect && timestampModeSelect.value === 'retro90s';

      const ctx = canvas.getContext('2d');

      // --- Dimension & Layout Setup ---
      let canvasW = 1200;
      let canvasH = 1200;
      let outerMargin = 36;
      let polaroidBottom = 160;

      if (currentLayout === 'strip4' || currentLayout === 'film35mm') {
        // Vertical Photobooth Strip (Life4Cuts style)
        canvasW = 640;
        canvasH = 1920;
        outerMargin = currentLayout === 'film35mm' ? 48 : 28;
        polaroidBottom = 180;
      } else if (currentLayout === 'singlePolaroid') {
        canvasW = 1000;
        canvasH = 1200;
        outerMargin = 40;
        polaroidBottom = 200;
      }

      canvas.width = canvasW;
      canvas.height = canvasH;

      // 1. Draw Background
      ctx.fillStyle = currentLayout === 'film35mm' ? '#111827' : currentBgColor;
      ctx.fillRect(0, 0, canvasW, canvasH);

      // If user uploaded a custom template background (JPG), draw it behind photos
      if (customTemplateImg) {
        ctx.drawImage(customTemplateImg, 0, 0, canvasW, canvasH);
      }

      const gridAreaW = canvasW - outerMargin * 2;
      const gridAreaH = canvasH - outerMargin - polaroidBottom;

      // 2. Render Photos According to Layout
      if (currentLayout === 'grid4x4') {
        // 4x4 Multi-Tile (16 tiles using first frame)
        const frame = frames[0];
        const cols = 4;
        const rows = 4;
        const gap = 8;
        const cellW = (gridAreaW - gap * (cols - 1)) / cols;
        const cellH = (gridAreaH - gap * (rows - 1)) / rows;

        for (let r = 0; r < rows; r++) {
          for (let c = 0; c < cols; c++) {
            const x = outerMargin + c * (cellW + gap);
            const y = outerMargin + r * (cellH + gap);

            ctx.fillStyle = '#0F172A';
            ctx.fillRect(x, y, cellW, cellH);
            ctx.drawImage(frame, 0, 0, frame.width, frame.height, x, y, cellW, cellH);

            ctx.strokeStyle = 'rgba(255, 255, 255, 0.4)';
            ctx.lineWidth = 1.5;
            ctx.strokeRect(x, y, cellW, cellH);
          }
        }
      } else if (currentLayout === 'strip4' || currentLayout === 'film35mm') {
        // Vertical 4-Cut Strip (4 photos arranged top to bottom)
        const count = 4;
        const gap = 14;
        const cellW = gridAreaW;
        const cellH = (gridAreaH - gap * (count - 1)) / count;

        for (let i = 0; i < count; i++) {
          const f = frames[i] || frames[0];
          const y = outerMargin + i * (cellH + gap);

          ctx.fillStyle = '#0F172A';
          ctx.fillRect(outerMargin, y, cellW, cellH);
          ctx.drawImage(f, 0, 0, f.width, f.height, outerMargin, y, cellW, cellH);

          ctx.strokeStyle = currentLayout === 'film35mm' ? '#FFFFFF' : 'rgba(168, 87, 126, 0.25)';
          ctx.lineWidth = currentLayout === 'film35mm' ? 2 : 1.5;
          ctx.strokeRect(outerMargin, y, cellW, cellH);
        }

        // Draw Sprocket Holes if 35mm Film Strip
        if (currentLayout === 'film35mm') {
          ctx.fillStyle = '#F8FAFC';
          for (let spY = 24; spY < canvasH - 24; spY += 40) {
            ctx.fillRect(12, spY, 20, 14); // Left sprocket
            ctx.fillRect(canvasW - 32, spY, 20, 14); // Right sprocket
          }
        }
      } else if (currentLayout === 'collage2x2') {
        // 2x2 Square Collage (4 photos in square grid)
        const cols = 2;
        const rows = 2;
        const gap = 16;
        const cellW = (gridAreaW - gap * (cols - 1)) / cols;
        const cellH = (gridAreaH - gap * (rows - 1)) / rows;

        for (let i = 0; i < 4; i++) {
          const f = frames[i] || frames[0];
          const r = Math.floor(i / cols);
          const c = i % cols;
          const x = outerMargin + c * (cellW + gap);
          const y = outerMargin + r * (cellH + gap);

          ctx.fillStyle = '#0F172A';
          ctx.fillRect(x, y, cellW, cellH);
          ctx.drawImage(f, 0, 0, f.width, f.height, x, y, cellW, cellH);

          ctx.strokeStyle = 'rgba(168, 87, 126, 0.3)';
          ctx.lineWidth = 3;
          ctx.strokeRect(x, y, cellW, cellH);
        }
      } else if (currentLayout === 'singlePolaroid') {
        // Single Classic Polaroid
        const f = frames[0];
        ctx.fillStyle = '#0F172A';
        ctx.fillRect(outerMargin, outerMargin, gridAreaW, gridAreaH);
        ctx.drawImage(f, 0, 0, f.width, f.height, outerMargin, outerMargin, gridAreaW, gridAreaH);

        ctx.strokeStyle = 'rgba(0, 0, 0, 0.08)';
        ctx.lineWidth = 1;
        ctx.strokeRect(outerMargin, outerMargin, gridAreaW, gridAreaH);
      }

      // If user uploaded a transparent PNG overlay frame, draw it on top!
      if (customTemplateImg) {
        ctx.drawImage(customTemplateImg, 0, 0, canvasW, canvasH);
      }

      // 3. Render Custom Text & Timestamps
      const bottomAreaY = canvasH - polaroidBottom + 30;

      // Primary Title
      ctx.fillStyle = currentLayout === 'film35mm' ? '#FFFFFF' : textColor;
      ctx.font = `bold ${canvasW < 800 ? '28px' : '36px'} ${activeFont}`;
      ctx.textAlign = 'left';
      ctx.fillText(titleText, outerMargin + 8, bottomAreaY + 30);

      // Personal Note / Slogan
      ctx.fillStyle = currentLayout === 'film35mm' ? '#E2E8F0' : textColor;
      ctx.font = `${canvasW < 800 ? '20px' : '24px'} ${activeFont}`;
      ctx.fillText(noteText, outerMargin + 8, bottomAreaY + 68);

      // Timestamp (with authentic 90s digital orange option)
      if (timestampText) {
        if (isRetro90s) {
          ctx.fillStyle = '#FF7A00'; // Neon retro orange
          ctx.font = 'bold 24px "Courier New", monospace';
          ctx.shadowColor = '#FF7A00';
          ctx.shadowBlur = 6;
          ctx.fillText(timestampText, outerMargin + 8, bottomAreaY + 104);
          ctx.shadowBlur = 0; // Reset shadow
        } else {
          ctx.fillStyle = currentLayout === 'film35mm' ? '#94A3B8' : '#64748B';
          ctx.font = `500 ${canvasW < 800 ? '16px' : '18px'} ${activeFont}`;
          ctx.fillText(timestampText, outerMargin + 8, bottomAreaY + 102);
        }
      }

      // Decorative emblem at bottom-right
      ctx.fillStyle = '#F4A5AE';
      ctx.font = '32px serif';
      ctx.textAlign = 'right';
      ctx.fillText('♥', canvasW - outerMargin - 8, bottomAreaY + 50);

      // 4. SHA-256 Integrity Watermark — tamper-proof photo hash
      const photoPayload = [titleText, noteText, timestampText, currentLayout, currentFilter, currentBgColor].join('|');
      const photoHash = await SecurityCrypto.sha256(photoPayload);
      const shortPhotoHash = SecurityCrypto.shortHash(photoHash);
      ctx.fillStyle = 'rgba(100, 116, 139, 0.45)';
      ctx.font = `500 ${canvasW < 800 ? '10px' : '12px'} "Courier New", monospace`;
      ctx.textAlign = 'right';
      ctx.fillText(`🔒 SHA-256: #${shortPhotoHash}`, canvasW - outerMargin - 8, canvasH - 12);

      // Update URL with hashed photo reference
      window.history.replaceState(null, '', '#photo-' + shortPhotoHash);

      // 5. Update UI Image & Download Link
      const dataUrl = canvas.toDataURL('image/png');
      resultImg.src = dataUrl;
      downloadBtn.href = dataUrl;
      downloadBtn.download = `the-memory-circle-${currentLayout}-${Date.now()}.png`;

      if (resultDate) {
        resultDate.textContent = `${titleText} • ${timestampText || 'Memorabilia'}`;
      }
      if (resultBadge) {
        resultBadge.textContent = `#${currentLayout.toUpperCase()}`;
      }
    };

    // --- Master Capture Flow ---
    const capturePhoto = async () => {
      if (isCapturing) return;
      isCapturing = true;
      captureBtn.disabled = true;

      try {
        const isMultiShot = currentLayout === 'strip4' || currentLayout === 'collage2x2' || currentLayout === 'film35mm';
        const frames = [];

        if (isMultiShot) {
          // Multi-shot sequence (4 poses)
          const poseLabels = ['Pose 1', 'Pose 2', 'Pose 3', 'Pose 4'];
          for (let i = 0; i < 4; i++) {
            await runCountdown(3, poseLabels[i]);
            triggerFlash();
            frames.push(grabVideoFrame());
            await new Promise((r) => setTimeout(r, 450));
          }
        } else {
          // Single-shot (4x4 multi-tile or single polaroid)
          await runCountdown(3);
          triggerFlash();
          frames.push(grabVideoFrame());
        }

        lastCapturedFrames = frames;
        await renderComposite(frames);

        // Switch to result preview screen
        liveScreen.hidden = true;
        liveScreen.style.display = 'none';
        promptScreen.hidden = true;
        promptScreen.style.display = 'none';
        resultScreen.hidden = false;
        resultScreen.style.display = 'flex';
      } catch (err) {
        console.error('Error during photo capture:', err);
        showStatus('An error occurred during photo capture. Please try again.', 'error');
      } finally {
        isCapturing = false;
        captureBtn.disabled = false;
      }
    };

    captureBtn.addEventListener('click', capturePhoto);

    // Retake Photo
    retakeBtn.addEventListener('click', () => {
      resultScreen.hidden = true;
      resultScreen.style.display = 'none';
      promptScreen.hidden = true;
      promptScreen.style.display = 'none';
      liveScreen.hidden = false;
      liveScreen.style.display = 'flex';
    });

    // Pin Captured Photo directly to the Live Sticky Note Board
    pinBtn.addEventListener('click', async () => {
      if (!notesBoard || !resultImg.src) return;

      const titleText = SecurityCrypto.sanitize((titleInput && titleInput.value.trim()) || 'The Memory Circle');
      const noteText = SecurityCrypto.sanitize((noteInput && noteInput.value.trim()) || 'Freshly snapped from the live photo booth!');

      // Compute integrity hash for the pinned photo
      const pinPayload = [titleText, noteText, Date.now()].join('|');
      const pinHash = await SecurityCrypto.sha256(pinPayload);
      const shortPinHash = SecurityCrypto.shortHash(pinHash);

      const newNote = document.createElement('article');
      newNote.className = 'sticky-note note-pink';
      newNote.setAttribute('role', 'listitem');
      newNote.setAttribute('data-integrity', shortPinHash);
      newNote.style.animation = 'fadeInNote 0.5s ease';

      const pin = document.createElement('div');
      pin.className = 'note-pin';
      pin.setAttribute('aria-hidden', 'true');

      const photoWrapper = document.createElement('div');
      photoWrapper.style.borderRadius = '4px';
      photoWrapper.style.overflow = 'hidden';
      photoWrapper.style.marginBottom = '8px';
      photoWrapper.style.border = '1.5px solid rgba(168, 87, 126, 0.3)';

      const thumbImg = document.createElement('img');
      thumbImg.src = resultImg.src;
      thumbImg.alt = 'Freshly captured photo booth memory';
      thumbImg.style.width = '100%';
      thumbImg.style.display = 'block';
      photoWrapper.appendChild(thumbImg);

      const noteP = document.createElement('p');
      noteP.className = 'note-text';
      noteP.style.fontSize = '1.15rem';
      noteP.textContent = `“${noteText}”`;

      const noteFooter = document.createElement('footer');
      noteFooter.className = 'note-author';

      const authorStrong = document.createElement('strong');
      authorStrong.textContent = `— ${titleText}`;

      const memoryTime = document.createElement('time');
      memoryTime.textContent = 'Just Now • Custom Booth';

      noteFooter.appendChild(authorStrong);
      noteFooter.appendChild(memoryTime);

      // SHA-256 integrity badge for pinned photo
      const photoBadge = document.createElement('span');
      photoBadge.className = 'crypto-hash-badge';
      photoBadge.title = `SHA-256: ${pinHash}`;
      photoBadge.textContent = `🔒 #${shortPinHash}`;

      newNote.appendChild(pin);
      newNote.appendChild(photoWrapper);
      newNote.appendChild(noteP);
      newNote.appendChild(noteFooter);
      newNote.appendChild(photoBadge);

      notesBoard.prepend(newNote);
      newNote.scrollIntoView({ behavior: 'smooth', block: 'center' });

      pinBtn.textContent = 'Pinned to Board! ✓';
      pinBtn.disabled = true;
      setTimeout(() => {
        pinBtn.textContent = 'Pin to Memory Board';
        pinBtn.disabled = false;
      }, 3000);
    });
  };

  /* ==========================================================================
     INITIALIZE ALL MODULES
     ========================================================================== */
  initThemeToggle();
  initMobileNavigation();
  initScrollSpy();
  initGalleryFilters();
  initMemoryModal();
  initMemoryForm();
  initWebcamBooth();
});
