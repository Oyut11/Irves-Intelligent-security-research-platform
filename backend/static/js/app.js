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
  const layout   = document.getElementById("app-layout");
  const toggle   = document.getElementById("sidebar-toggle");
  const palette  = document.getElementById("command-palette");
  const pInput   = document.getElementById("palette-input");
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
    { label: "Projects",          href: "/",          icon: "folder" },
    { label: "New Scan",          href: "/scan",       icon: "search" },
    { label: "Live Scan View",    href: "/live-scan",  icon: "activity" },
    { label: "Runtime Workspace", href: "/runtime",    icon: "cpu" },
    { label: "Dashboard",         href: "/dashboard",  icon: "grid" },
    { label: "Reports",           href: "/reports",    icon: "file-text" },
    { label: "Settings",          href: "/settings",   icon: "settings" },
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
      const map = { ".apk": "android", ".ipa": "ios", ".exe": "desktop",
                    ".msi": "desktop", ".dmg": "desktop", ".deb": "desktop", ".rpm": "desktop" };
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

  // ── Active nav highlight ──────────────────────────────────────────────────
  const currentPath = window.location.pathname;
  document.querySelectorAll("[data-nav-href]").forEach(el => {
    const href = el.getAttribute("data-nav-href");
    if (currentPath === href || (href !== "/" && currentPath.startsWith(href))) {
      el.classList.add("active");
    }
  });

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
