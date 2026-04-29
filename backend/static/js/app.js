/**
 * IRVES — App Shell JavaScript
 *
 * Handles:
 *  - Sidebar collapse / expand
 *  - ⌘K / Ctrl+K command palette
 *  - Global drag-and-drop (Projects screen drop zone)
 *  - Active nav highlighting
 */

(function () {
  "use strict";

  // ── DOM refs ──────────────────────────────────────────────────────────────
  const layout = document.getElementById("app-layout");
  const toggle = document.getElementById("sidebar-toggle");
  const palette = document.getElementById("command-palette");
  const pInput = document.getElementById("palette-input");
  const dropZone = document.getElementById("drop-zone");

  // ── Sidebar ───────────────────────────────────────────────────────────────
  let sidebarCollapsed = localStorage.getItem("sidebar-collapsed") === "true";

  function applySidebarState() {
    if (!layout) return;
    layout.classList.toggle("sidebar-collapsed", sidebarCollapsed);
    if (toggle) {
      toggle.setAttribute("aria-expanded", String(!sidebarCollapsed));
      toggle.setAttribute("title", sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar");
    }
  }

  function toggleSidebar() {
    sidebarCollapsed = !sidebarCollapsed;
    localStorage.setItem("sidebar-collapsed", sidebarCollapsed);
    applySidebarState();
  }

  if (toggle) toggle.addEventListener("click", toggleSidebar);
  applySidebarState();

  // ── Command Palette ───────────────────────────────────────────────────────
  const NAV_ITEMS = [
    { label: "Projects", href: "/", icon: "folder" },
    { label: "New Scan", href: "/scan", icon: "search" },
    { label: "Runtime Workspace", href: "/runtime", icon: "cpu" },
    { label: "Dashboard", href: "/dashboard", icon: "grid" },
    { label: "Reports", href: "/reports", icon: "file-text" },
    { label: "Settings", href: "/settings", icon: "settings" },
  ];

  function openPalette() {
    if (!palette) return;
    palette.classList.add("open");
    if (pInput) { pInput.value = ""; pInput.focus(); renderPaletteResults(""); }
  }

  function closePalette() {
    if (!palette) return;
    palette.classList.remove("open");
  }

  function renderPaletteResults(query) {
    const list = document.getElementById("palette-results");
    if (!list) return;

    const q = query.toLowerCase().trim();
    const results = q
      ? NAV_ITEMS.filter(i => i.label.toLowerCase().includes(q))
      : NAV_ITEMS;

    list.innerHTML = results.map((item, idx) => `
      <a class="palette__result-item${idx === 0 ? " active" : ""}"
         href="${item.href}"
         data-palette-item>
        <span>${item.label}</span>
      </a>
    `).join("");
  }

  // Keyboard shortcut: ⌘K or Ctrl+K
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "k") {
      e.preventDefault();
      palette?.classList.contains("open") ? closePalette() : openPalette();
    }
    if (e.key === "Escape" && palette?.classList.contains("open")) {
      closePalette();
    }
  });

  // Close on overlay click (not on palette itself)
  if (palette) {
    palette.addEventListener("click", (e) => {
      if (e.target === palette) closePalette();
    });
  }

  // Search input filter
  if (pInput) {
    pInput.addEventListener("input", () => renderPaletteResults(pInput.value));
  }

  // Top bar search trigger
  const searchTrigger = document.getElementById("search-trigger");
  if (searchTrigger) searchTrigger.addEventListener("click", openPalette);

  // ── Drag & Drop (Projects drop zone) ────────────────────────────────────
  if (dropZone) {
    // Prevent default browser file open on drag
    ["dragenter", "dragover", "dragleave", "drop"].forEach(ev => {
      document.addEventListener(ev, e => e.preventDefault());
    });

    const ACCEPTED_EXTENSIONS = [".apk", ".ipa", ".exe", ".dmg", ".deb", ".rpm", ".msi"];

    document.addEventListener("dragenter", () => dropZone.classList.add("drag-over"));
    document.addEventListener("dragleave", (e) => {
      if (!e.relatedTarget || e.relatedTarget === document.documentElement) {
        dropZone.classList.remove("drag-over");
      }
    });

    document.addEventListener("drop", (e) => {
      dropZone.classList.remove("drag-over");
      const file = e.dataTransfer?.files?.[0];
      if (!file) return;

      const ext = "." + file.name.split(".").pop().toLowerCase();
      if (!ACCEPTED_EXTENSIONS.includes(ext)) {
        showToast(`Unsupported file type: ${ext}. Drop an APK, IPA, or executable.`);
        return;
      }

      // Navigate to New Scan with file context
      // In Phase 2 this will pre-populate the scan form
      sessionStorage.setItem("pending_file", file.name);
      sessionStorage.setItem("pending_platform", detectPlatform(ext));
      window.location.href = "/scan";
    });

    function detectPlatform(ext) {
      const map = {
        ".apk": "android", ".ipa": "ios", ".exe": "desktop",
        ".msi": "desktop", ".dmg": "desktop", ".deb": "desktop", ".rpm": "desktop"
      };
      return map[ext] || "desktop";
    }
  }

  // ── Toast ─────────────────────────────────────────────────────────────────
  function showToast(message, duration = 4000) {
    const existing = document.querySelector(".toast");
    if (existing) existing.remove();

    const toast = document.createElement("div");
    toast.className = "toast";
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), duration);
  }

  // Expose globally for HTMX use
  window.irves = { showToast, openPalette, closePalette, toggleSidebar };

  // ── SPA Window Manager (Preserve State) ───────────────────────────────────
  const isHeadless = new URLSearchParams(window.location.search).get('headless') === 'true';

  if (!isHeadless) {
    const frames = {};
    const mainContainer = document.getElementById('main-content');

    // Encapsulate the initially loaded server content into the first frame
    const initialWrapper = document.createElement('div');
    initialWrapper.className = 'screen-frame';
    initialWrapper.style.width = '100%';
    initialWrapper.style.height = '100%';

    while (mainContainer.firstChild) {
      initialWrapper.appendChild(mainContainer.firstChild);
    }
    mainContainer.appendChild(initialWrapper);
    frames[window.location.pathname + window.location.search] = initialWrapper;

    // ── Centralized SPA Navigation ──────────────────────────────────────
    function navigateTo(href) {
      if (!href) return;
      const currentUrl = window.location.pathname + window.location.search;
      if (href === currentUrl) return;

      let pathKey = href;
      const basePath = href.split('?')[0];

      // Runtime and Network are singletons; they manage state explicitly via url_update
      if (basePath === '/runtime' || basePath === '/network') {
          pathKey = basePath;
      } else if (!frames[pathKey]) {
          // If accessing an endpoint like /dashboard explicitly without params, 
          // try to rescue/reuse the active project frame if one exists
          if (!href.includes('?')) {
              const fallbackKey = Object.keys(frames).find(k => k.split('?')[0] === basePath);
              if (fallbackKey) {
                  pathKey = fallbackKey;
                  href = fallbackKey; // Sync the browser URL to the actual cached frame content
              }
          }
      }

      // Hide all frames
      Object.values(frames).forEach(f => { f.style.display = 'none'; });

      // Show existing or create new iframe
      if (frames[pathKey]) {
        frames[pathKey].style.display = 'block';
        // If it's an iframe, tell it the URL changed so it can react without reloading
        if (frames[pathKey].contentWindow) {
          frames[pathKey].contentWindow.postMessage({ type: 'url_update', href }, '*');
        } else {
          // For the initialWrapper, just dispatch an event
          window.dispatchEvent(new CustomEvent('url_update', { detail: { href } }));
        }
      } else {
        const iframe = document.createElement('iframe');
        const sep = href.includes('?') ? '&' : '?';
        iframe.src = href + sep + 'headless=true';
        iframe.style.width = '100%';
        iframe.style.height = '100%';
        iframe.style.border = 'none';
        iframe.className = 'screen-frame';
        mainContainer.appendChild(iframe);
        frames[pathKey] = iframe;
      }

      // Update UI active states in sidebar
      document.querySelectorAll('.nav-item').forEach(n => {
        const itemHref = n.getAttribute('href');
        // Highlight if paths match (ignoring query params for basic nav highlighting)
        const isActive = href.split('?')[0] === itemHref.split('?')[0];
        n.classList.toggle('active', isActive);
      });

      // Update URL without reloading the browser
      window.history.pushState({}, '', href);
    }

    // Intercept all internal links in the main window
    document.addEventListener('click', (e) => {
      const link = e.target.closest('a');
      if (!link) return;

      const href = link.getAttribute('href');
      // Only intercept relative paths or same-origin paths, skipping hashes/external/downloads
      if (!href || href.startsWith('http') || href.startsWith('#') || link.getAttribute('target') === '_blank' || link.hasAttribute('download')) return;

      e.preventDefault();
      navigateTo(href);
    });

    // Handle messages from headless iframes
    window.addEventListener('message', (e) => {
      if (e.data && e.data.type === 'navigate') {
        navigateTo(e.data.href);
      }
    });

    // Handle browser back/forward buttons
    window.addEventListener('popstate', () => {
      const path = window.location.pathname;
      document.querySelectorAll('.nav-item').forEach(n => {
        const itemHref = n.getAttribute('href');
        n.classList.toggle('active', itemHref.split('?')[0] === path.split('?')[0]);
      });
      Object.values(frames).forEach(f => { f.style.display = 'none'; });
      
      const fullHref = window.location.pathname + window.location.search;
      let pathKey = fullHref;
      const basePath = path.split('?')[0];

      // Runtime and Network are singletons
      if (basePath === '/runtime' || basePath === '/network') {
          pathKey = basePath;
      }

      if (frames[pathKey]) {
          frames[pathKey].style.display = 'block';
          if (frames[pathKey].contentWindow) {
              frames[pathKey].contentWindow.postMessage({ type: 'url_update', href: fullHref }, '*');
          } else {
              window.dispatchEvent(new CustomEvent('url_update', { detail: { href: fullHref } }));
          }
      }
    });
  } else {
    // ── Headless Mode (inside an iframe) ───────────────────────────────
    document.body.classList.add('headless-mode');

    // Intercept all internal clicks and notify the parent instead of navigating locally
    document.addEventListener('click', (e) => {
      const link = e.target.closest('a');
      if (!link) return;

      const href = link.getAttribute('href');
      if (!href || href.startsWith('http') || href.startsWith('#') || link.getAttribute('target') === '_blank') return;

      e.preventDefault();
      window.parent.postMessage({ type: 'navigate', href }, '*');
    });
  }

  // ── Pending file (from drop on another page) ──────────────────────────────
  const pendingFile = sessionStorage.getItem("pending_file");
  if (pendingFile && window.location.pathname === "/scan") {
    const targetInput = document.getElementById("scan-target-display");
    const platformSelect = document.getElementById("platform-select");
    if (targetInput) targetInput.textContent = pendingFile;
    if (platformSelect) {
      const plat = sessionStorage.getItem("pending_platform") || "android";
      platformSelect.value = plat;
    }
    sessionStorage.removeItem("pending_file");
    sessionStorage.removeItem("pending_platform");
  }
})();
