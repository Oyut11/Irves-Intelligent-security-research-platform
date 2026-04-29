# Runtime Workspace

The **Runtime Workspace** is IRVES's live dynamic instrumentation environment for Android applications. It lets you attach to running apps, inject hooks, intercept API calls, and observe behavior in real time — all from your browser.

---

## Table of Contents

- [Concept](#concept)
- [Supported Engines](#supported-engines)
- [Setup Workflow](#setup-workflow)
- [Built-in Hooks](#built-in-hooks)
- [Custom Scripts](#custom-scripts)
- [AI Runtime Partner](#ai-runtime-partner)
- [Auto-Pivot](#auto-pivot)
- [Troubleshooting](#troubleshooting)

---

## Concept

Static analysis (APKTool, JADX) shows you what code *exists*. Runtime analysis shows you what code *executes*:

- Which network endpoints does the app actually call?
- What encryption keys are generated at runtime?
- How does the app detect root / tampering?
- What Intents are fired between components?

The Runtime Workspace bridges the gap between static findings and dynamic proof-of-concept by giving you a live JavaScript injection environment powered by Frida or Xposed.

### Instrumentation Engines

#### Frida

**Frida** is a dynamic instrumentation toolkit that lets you inject JavaScript into running processes. It works by:
1. Attaching to or spawning the target process
2. Loading a JavaScript engine (Duktape) into the process memory
3. Providing APIs to hook functions, read/write memory, and call methods
4. Streaming script output back to your control interface

**Why use Frida?**
- **Full control** — Hook any Java method, native function, or system call
- **Native layer access** — Instrument C/C++ code in .so libraries
- **Real-time interaction** — Call functions, modify arguments, change return values
- **No APK modification** — Works on the original app without repackaging
- **Rich ecosystem** — Extensive library of pre-built hooks and tools

**How Frida works:**
Frida uses a client-server architecture:
- **frida-server** runs on the Android device (requires root)
- **frida-client** (IRVES) connects to the server via USB or network
- When you inject a script, frida-server loads it into the target process
- The script executes in the process context with full access to memory and APIs

**Why rooting is needed for Frida:**
Frida requires root because it must:
- **Attach to arbitrary processes** — Android's security model prevents one app from attaching to another without root
- **Load code into process memory** — Injecting the JavaScript engine requires `ptrace` or similar capabilities
- **Bypass SELinux restrictions** — Modern Android enforces strict access controls; root bypasses these
- **Run frida-server** — The server binary needs elevated permissions to interact with other processes

Without root, Frida cannot attach to system processes or third-party apps, limiting it to your own debuggable applications.

#### Xposed

**Xposed** is a framework for modifying Android apps without APK repackaging. It works at the framework level by:
1. Replacing the Android runtime (Zygote) with a modified version
2. Loading Xposed modules before any app starts
3. Hooking methods at the Java framework level (before app code runs)
4. Allowing modules to modify app behavior transparently

**Why use Xposed?**
- **No root required for analysis** — Works on non-rooted devices via LSPatch
- **Framework-level hooks** — Intercept calls before app code executes
- **Persistent instrumentation** — Hooks remain active across app restarts
- **Module ecosystem** — Large community of pre-built modules

**How Xposed works:**
Xposed modifies the Android Zygote process (the parent of all app processes). When an app spawns:
1. Xposed's modified Zygote loads Xposed modules
2. Modules register hooks for specific methods
3. When the hooked method is called, Xposed intercepts it
4. The module can modify arguments, return values, or skip the original method

**Limitations:**
- Requires Xposed framework installation (root) or LSPatch (non-root)
- Cannot hook native code directly
- Framework-level only — less granular than Frida
- May trigger anti-tampering detection

#### LSPatch

**LSPatch** is a non-root alternative to Xposed that embeds Xposed modules directly into APK files. It works by:
1. Decompiling the target APK
2. Injecting Xposed framework code and selected modules
3. Repackaging and signing the modified APK
4. Reinstalling the patched app (replaces original)

**Why use LSPatch?**
- **No root required** — Works on any Android device
- **Targeted instrumentation** — Only affects the patched app
- **No system modification** — Doesn't require framework changes
- **Compatible with production devices** — Suitable for testing on non-rooted phones

**How LSPatch works:**
LSPatch uses APKTool and smali injection:
1. Extracts the APK's DEX code
2. Adds Xposed Bridge classes to the DEX
3. Injects module hooks as smali bytecode
4. Rebuilds the APK with a new signature
5. Installs the patched app (uninstalls original)

**Trade-offs:**
- **Pros** — No root, works on any device, isolated to target app
- **Cons** — Requires app reinstall, signature mismatch may break some apps, cannot update without re-patching

---

## Supported Engines

| Engine | Requirements | Best For |
|--------|-------------|----------|
| **Frida** | Rooted device + frida-server | Full control, all hooks, native layer |
| **Xposed / LSPatch** | Non-rooted device | Quick start, no system modification |

### Frida (Root Required)

Frida is the gold standard for mobile instrumentation. It injects a JavaScript engine into the target process, allowing you to hook Java methods, native functions, and intercept system calls.

**Prerequisites:**
- Android device with root access (Magisk recommended)
- ADB debugging enabled
- frida-server binary on device (IRVES can push it automatically)

**Connection flow:**
1. Connect device via USB
2. IRVES detects ADB device
3. Push frida-server if missing
4. Attach or spawn target app
5. Inject hooks and receive live output

### Xposed / LSPatch (Non-Root)

LSPatch embeds Xposed modules directly into an APK, repackages it, and reinstalls — no root required.

**Prerequisites:**
- ADB debugging enabled
- Java runtime on host (for APK patching)

**Connection flow:**
1. Connect device via USB
2. Select target app from installed packages
3. IRVES patches APK with instrumentation hooks
4. Reinstalls patched APK
5. Streams logcat output via WebSocket

---

## Setup Workflow

### 1. Connect Your Device

Connect an Android device via USB with debugging enabled. The Runtime Workspace automatically polls for ADB devices every few seconds.

### 2. Run Pre-flight Check

Click **Check Pre-flight** to verify:
- ADB connection
- Frida/Python availability (for Frida engine)
- Java/ADB availability (for Xposed engine)

### 3. Select Engine and App

Choose your engine from the dropdown:
- **Frida (Root Required)** — for full instrumentation power
- **Xposed (Non-Root)** — for quick no-root testing

Select the target app from the package list (click ⟳ Fetch to populate).

### 4. Start Session

Click **▶ Connect** to:
- **Attach** — hook into the already-running app process
- **Spawn** — restart the app under instrumentation (catches early initialization)

### 5. Inject Hooks

Use **Guided Hooks** to select from built-in hooks, or paste custom Frida JavaScript into the **Script Editor** and click **Run Script**.

---

## Built-in Hooks

| Hook | Category | Risk | What It Does |
|------|----------|------|--------------|
| **App Context & Info Extractor** | Reconnaissance | Low | Pulls hidden metadata from the live app context |
| **SSL Pinning Bypass** | Network Security | High | Disables OkHttp3 / TrustManager certificate checks |
| **Root Detection Bypass** | Anti-Tamper | Medium | Patches RootBeer, SuperUser, blocks `su` checks |
| **Crypto Operation Capture** | Cryptography | High | Intercepts `javax.crypto.Cipher` calls, logs plaintext |
| **Network Connection Monitor** | Network Security | Low | Hooks `URL.openConnection`, logs every outbound request |
| **Android Intent Monitor** | IPC / Components | Low | Logs all explicitly-created Intents with destinations |
| **Zymbiote Stealth Cloak** | Anti-Detection | High | Hides Frida from `/proc/self/maps`, masks thread names |
| **BoringSSL Native Capture** | Network Security | High | Hooks `SSL_read`/`SSL_write` in native layer for plaintext |

---

## Custom Scripts

The **Script Editor** accepts standard Frida JavaScript. Minimal example:

```javascript
Java.perform(function() {
  var Activity = Java.use("android.app.Activity");
  Activity.onCreate.overload("android.os.Bundle").implementation = function(bundle) {
    send("[IRVES] Activity created: " + this.getClass().getName());
    this.onCreate(bundle);
  };
});
```

Click **Run Script** to inject live. Output appears in the **Live Output** panel in real time.

---

## AI Runtime Partner

The **Irves AI Partner** drawer (bottom-right) connects to the same AI engine used in chat, but with full runtime context:

- **Current device** and **app package**
- **Active hooks** and their outputs
- **Session history** of injections and errors

**Quick actions:**
- **Analyze Logs** — AI reviews output and suggests next hooks
- **Suggest Hook** — AI generates custom Frida script for your target
- **Bypass Root Detection** — AI crafts evasion script based on current app behavior
- **SSL Pinning Bypass** — AI injects context-aware bypass
- **Dump Unpacked DEX** — AI generates memory dump script

You can also type natural language requests: *"The app crashes when I hook URL.openConnection — can you try a different approach?"*

---

## Auto-Pivot

When a hook fails, crashes, or produces an unexpected error, IRVES **automatically triggers an AI pivot**:

1. **Error detected** in WebSocket stream (e.g., injection failure, Frida script crash)
2. **Session history** and **finding context** are sent to AI
3. **AI generates** a new strategy (different hook point, fallback approach, or workaround)
4. **New script streamed** back to the workspace in real time
5. You can **auto-inject** the suggested fix with one click

This closes the loop between human operator and AI assistant — you don't need to copy-paste errors into chat manually.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "No ADB devices" | USB debugging off, bad cable, no driver | Enable developer options + USB debugging; try different cable |
| "frida-server not running" | Frida server not on device | Click **⚡ Push frida-server** in the toast notification |
| "Attach failed" | Wrong package name, app not running | Verify package name with `adb shell pm list packages` |
| "Inject failed" | Syntax error in script, class not found | Check Live Output for stack trace; use AI Partner for fix |
| "Zygote crash" | Aggressive hooking at spawn time | Switch to **Attach** mode instead of **Spawn** |
| "RASP detected Frida" | App has anti-instrumentation | Inject **Zymbiote Stealth Cloak** before other hooks |
| Empty output after inject | Hook class not loaded yet | Retry after app initializes, or use `setTimeout` retry loop |

---

## Security Notes

- **Root required** for Frida — this modifies the device security posture
- **Patched APKs** from LSPatch should be used only in testing environments
- **Hook injection** can destabilize apps; always test on non-production builds
