        (function () {
            // ── State ──────────────────────────────────────────────────────────────
            let selectedDevice = null;  // Frida device id (for Frida engine)
            let selectedSerial = null;  // ADB serial (for Xposed engine + general ADB ops)
            let selectedPackage = null;
            let selectedEngine = 'frida'; // 'frida' | 'xposed'
            let activeSession = null;
            let websocket = null;
            let activeHooks = [];
            let toastSerial = null;  // ADB serial waiting for frida-server
            let setupEventSource = null;
            let devicePollTimer = null;
            let knownAdbSerials = new Set();
            let fridaReady = false;
            let xposedReady = false;  // ADB device found, Xposed engine selected
            let pendingScript = null;  // queued script; injected once 'attached' fires
            let pivotBannerEl = null;  // output-panel banner element for the current AI pivot

            // ── Runtime state exposed for AI partner ────────────────────────────────
            window._irvesRuntimeState = {
                engine: selectedEngine,
                fridaReady: fridaReady,
                xposedReady: xposedReady,
                device: selectedDevice,
                serial: selectedSerial,
                package: selectedPackage,
                websocketConnected: false,
                activeHooks: [],
                sessionActive: false,
                deviceLabel: 'Scanning for devices…',
            };
            function _syncRuntimeState() {
                window._irvesRuntimeState.engine = selectedEngine;
                window._irvesRuntimeState.fridaReady = fridaReady;
                window._irvesRuntimeState.xposedReady = xposedReady;
                window._irvesRuntimeState.device = selectedDevice;
                window._irvesRuntimeState.serial = selectedSerial;
                window._irvesRuntimeState.package = selectedPackage;
                window._irvesRuntimeState.websocketConnected = !!(websocket && websocket.readyState === WebSocket.OPEN);
                window._irvesRuntimeState.activeHooks = activeHooks.map(function(h) { return h.hookName || h; });
                window._irvesRuntimeState.sessionActive = !!websocket;
                const dl = document.getElementById('device-label');
                if (dl) window._irvesRuntimeState.deviceLabel = dl.textContent;
            }

            // ── DOM refs ────────────────────────────────────────────────────────────
            const preflightBtn = document.getElementById('preflight-btn');
            const preflightPanel = document.getElementById('preflight-panel');
            const runScriptBtn = document.getElementById('run-script-btn');
            const clearOutputBtn = document.getElementById('clear-output-btn');
            const clearOutputBtn2 = document.getElementById('clear-output-btn-2');
            const clearLogsBtn = document.getElementById('clear-logs-btn');
            const saveHookBtn = document.getElementById('save-hook-btn');
            const guidedHooksBtn = document.getElementById('guided-hooks-btn');
            const continueRuntimeBtn = document.getElementById('continue-runtime-btn');
            const outputStream = document.getElementById('output-stream');
            const logsStream = document.getElementById('logs-stream');
            const hooksList = document.getElementById('hooks-list');
            const scriptEditor = document.getElementById('frida-script-editor');
            const deviceDot = document.getElementById('device-status-dot');
            const deviceLabel = document.getElementById('device-label');
            const processLabel = document.getElementById('process-label');
            const fridaToast = document.getElementById('frida-toast');
            const fridaToastSub = document.getElementById('frida-toast-sub');
            const fridaToastPushBtn = document.getElementById('frida-toast-push-btn');
            const fridaToastDismiss = document.getElementById('frida-toast-dismiss');
            const wizardOverlay = document.getElementById('frida-wizard-overlay');
            const wizardSteps = document.getElementById('wizard-steps');
            const wizardStartBtn = document.getElementById('wizard-start-btn');
            const wizardCancelBtn = document.getElementById('wizard-cancel-btn');
            const wizardClose = document.getElementById('frida-wizard-close');

            // ── Event wiring ────────────────────────────────────────────────────────
            document.getElementById('runtime-docs-btn')?.addEventListener('click', () => {
                window.location.href = '/docs/runtime-workspace';
            });
            preflightBtn?.addEventListener('click', () => {
                const visible = preflightPanel.style.display !== 'none';
                preflightPanel.style.display = visible ? 'none' : 'block';
                if (!visible) runPreflight();
            });
            clearOutputBtn?.addEventListener('click', () => { outputStream.innerHTML = ''; });
            clearOutputBtn2?.addEventListener('click', () => { outputStream.innerHTML = ''; });
            clearLogsBtn?.addEventListener('click', () => { logsStream.innerHTML = ''; });
            runScriptBtn?.addEventListener('click', runFridaScript);
            saveHookBtn?.addEventListener('click', saveCurrentHook);
            guidedHooksBtn?.addEventListener('click', showGuidedHooks);
            continueRuntimeBtn?.addEventListener('click', startRuntimeSession);
            document.getElementById('connect-session-btn')?.addEventListener('click', () => {
                if (websocket && websocket.readyState === WebSocket.OPEN) {
                    disconnectSession();
                } else {
                    startRuntimeSession();
                }
            });

            // App Selector logic — keep process-label in sync for any legacy reads
            const appSelector = document.getElementById('app-selector');
            const engineSelector = document.getElementById('engine-selector');
            function getSelectedPackage() {
                return appSelector?.value?.trim() || '';
            }

            // Expose for agentic AI partner
            window.irvesRunScript = runFridaScript;
            window.irvesInjectHook = injectHook;
            function getEngine() {
                return engineSelector?.value || 'frida';
            }
            appSelector?.addEventListener('change', (e) => {
                const newPackage = e.target.value;
                selectedPackage = newPackage;
                _syncRuntimeState();
                if (processLabel) processLabel.textContent = newPackage;

                // If there's an active session with a different package, disconnect it
                if (selectedPackage && selectedPackage !== newPackage) {
                    if (websocket && websocket.readyState === WebSocket.OPEN) {
                        addOutput(`⚠ Switching app from ${escapeHtml(selectedPackage)} to ${escapeHtml(newPackage)} — disconnecting previous session...`, 'warn');
                        disconnectSession();
                    }
                }
            });
            // Initialise processLabel from selector on load
            if (processLabel && appSelector) processLabel.textContent = appSelector.value;

            // Engine selector: update state + UI hints
            engineSelector?.addEventListener('change', () => {
                selectedEngine = getEngine();
                _syncRuntimeState();
                const isXposed = selectedEngine === 'xposed';
                // Script editor is Frida-specific (Xposed uses logcat bridge)
                const editorPanel = document.getElementById('script-editor-panel');
                if (editorPanel) {
                    editorPanel.style.opacity = isXposed ? '0.4' : '1';
                    editorPanel.title = isXposed
                        ? 'Script editor is not used for Xposed. Hooks are always-on via TrustMeAlready module.'
                        : '';
                }
                addOutput(
                    isXposed
                        ? '⟳ Engine: Xposed (LSPatch) — connect opens a logcat stream, hooks are always active.'
                        : '⟳ Engine: Frida — connect opens a Frida WebSocket session.',
                    'info'
                );
                // Re-evaluate if connect button should be enabled
                _updateConnectBtn();
            });
            selectedEngine = getEngine(); // initialise from DOM

            document.getElementById('btn-fetch-apps')?.addEventListener('click', () => {
                const serial = toastSerial;
                if (!serial) {
                    addOutput('⚠ No ADB device known. Connect phone first.', 'warn');
                    return;
                }

                const btn = document.getElementById('btn-fetch-apps');
                const originalText = btn.textContent;
                btn.textContent = '...';
                btn.disabled = true;

                fetch(`/api/runtime/apps/${serial}`)
                    .then(r => r.json())
                    .then(data => {
                        btn.textContent = originalText;
                        btn.disabled = false;

                        if (data.status === 'success') {
                            const selector = document.getElementById('app-selector');
                            selector.innerHTML = '<option value="">Select App</option>';
                            data.packages.forEach(pkg => {
                                const opt = document.createElement('option');
                                opt.value = pkg;
                                opt.textContent = pkg;
                                selector.appendChild(opt);
                            });
                            addOutput(`✓ Fetched ${data.packages.length} installed packages from device.`, 'success');
                        } else {
                            addOutput(`⚠ Failed to fetch apps: ${data.message}`, 'error');
                        }
                    })
                    .catch(err => {
                        btn.textContent = originalText;
                        btn.disabled = false;
                        addOutput(`⚠ Error fetching apps: ${err}`, 'error');
                    });
            });

            // Header: Setup Engine button
            document.getElementById('setup-engine-btn')?.addEventListener('click', () => {
                const engine = document.getElementById('engine-selector')?.value || 'frida';
                if (toastSerial) {
                    openWizard(toastSerial, engine);
                } else {
                    fetch('/api/runtime/adb-devices').then(r => r.json()).then(devs => {
                        if (devs.length > 0) {
                            toastSerial = devs[0].serial;
                            openWizard(toastSerial, engine);
                        } else {
                            addOutput('⚠ No ADB device detected. Connect phone via USB first.', 'warn');
                        }
                    });
                }
            });

            // Toast buttons
            fridaToastPushBtn?.addEventListener('click', () => {
                hideToast();
                if (toastSerial) openWizard(toastSerial, 'frida');
            });
            fridaToastDismiss?.addEventListener('click', hideToast);

            // Wizard start button — read package from visible appSelector
            wizardStartBtn?.addEventListener('click', () => {
                if (!toastSerial) { addOutput('⚠ No device serial known.', 'warn'); return; }
                const pkg = getSelectedPackage();
                runWizardSetup(toastSerial, (pkg && !pkg.startsWith('No ') && !pkg.startsWith('Select')) ? pkg : null);
            });

            // ── Connect button enable/disable helper ─────────────────────────────
            function _updateConnectBtn() {
                const connectBtn = document.getElementById('connect-session-btn');
                if (!connectBtn) return;
                const eng = getEngine();
                const ready = eng === 'xposed' ? (xposedReady || !!selectedSerial) : fridaReady;
                if (ready) {
                    connectBtn.disabled = false;
                    connectBtn.style.opacity = '1';
                } else {
                    connectBtn.disabled = true;
                    connectBtn.style.opacity = '0.5';
                }
            }

            // ── Utilities ───────────────────────────────────────────────────────────
            function escapeHtml(str) {
                if (!str) return '';
                return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            }

            function addOutput(msg, type = 'info') {
                if (!outputStream) return;
                const now = new Date();
                const ts = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;
                const colors = { success: 'var(--success)', error: 'var(--critical)', warn: 'var(--warn, #f59e0b)', info: 'var(--text-primary)' };
                const line = document.createElement('div');
                line.className = 'output-line';
                line.innerHTML = `<span class="output-line__ts">[${ts}]</span> <span class="output-line__msg" style="color:${colors[type] || colors.info};">${escapeHtml(msg)}</span>`;
                outputStream.appendChild(line);
                outputStream.scrollTop = outputStream.scrollHeight;
            }

            function addLog(msg, type = 'info') {
                if (!logsStream) return;
                const now = new Date();
                const ts = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;
                const line = document.createElement('div');
                line.className = `log-line log-line--${type}`;
                line.innerHTML = `<span style="color:var(--text-faint);">[${ts}]</span> ${escapeHtml(msg)}`;
                logsStream.appendChild(line);
                logsStream.scrollTop = logsStream.scrollHeight;
            }

            // ── Device bar ──────────────────────────────────────────────────────────
            function setDeviceBar(state, label) {
                if (deviceDot) deviceDot.className = `status-dot status-dot--${state === 'ok' ? 'ok' : state === 'warn' ? 'warn' : 'waiting'}`;
                if (deviceLabel) deviceLabel.textContent = label;
            }

            // ── Toast (frida-server not running) ────────────────────────────────────
            function showToast(serial, model) {
                if (!fridaToast) return;
                toastSerial = serial;
                if (fridaToastSub) fridaToastSub.textContent = model ? `${model} — push frida-server to start Runtime Analysis` : 'Push frida-server to start Runtime Analysis';
                fridaToast.classList.add('frida-toast--visible');
            }
            function hideToast() {
                fridaToast?.classList.remove('frida-toast--visible');
            }

            // ── Wizard ──────────────────────────────────────────────────────────────
            const FRIDA_STEPS = [
                { id: 'arch', label: 'Detect device CPU architecture' },
                { id: 'download', label: 'Download matching frida-server binary' },
                { id: 'push', label: 'Push binary to /data/local/tmp/' },
                { id: 'chmod', label: 'Set execute permission (chmod 755)' },
                { id: 'start', label: 'Start frida-server as background daemon' },
            ];

            const XPOSED_STEPS = [
                { id: 'prepare', label: 'Download LSPatch + bypass modules' },
                { id: 'extract', label: 'Extract original APK from device' },
                { id: 'patch', label: 'Patch APK with LSPatch and Re-Sign' },
                { id: 'install', label: 'Uninstall & Install Patched Application' },
                { id: 'cleanup', label: 'Clean up workspace' },
            ];

            let wizardEngine = 'frida';

            function openWizard(serial, engine) {
                toastSerial = serial;
                wizardEngine = engine || 'frida';
                const steps = wizardEngine === 'frida' ? FRIDA_STEPS : XPOSED_STEPS;

                const titleEl = document.getElementById('wizard-title');
                if (titleEl) {
                    titleEl.textContent = wizardEngine === 'frida' ? '⚡ Push frida-server to Device' : '⚡ Setup Non-Root Xposed';
                }

                if (wizardSteps) {
                    wizardSteps.innerHTML = steps.map(s => `
                <div class="wizard-step" id="wstep-${s.id}">
                    <span class="wizard-step__icon wizard-step__icon--pending">···</span>
                    <span class="wizard-step__label">${escapeHtml(s.label)}</span>
                </div>`).join('');
                }
                if (wizardStartBtn) { wizardStartBtn.disabled = false; wizardStartBtn.textContent = 'Run Setup'; }
                if (wizardOverlay) wizardOverlay.classList.add('visible');
            }

            function closeWizard() {
                if (wizardOverlay) wizardOverlay.classList.remove('visible');
                if (setupEventSource) { setupEventSource.close(); setupEventSource = null; }
            }

            function updateWizardStep(id, state, detail) {
                const el = document.getElementById(`wstep-${id}`);
                if (!el) return;
                // 'done' from backend maps to 'ok' for icon display
                const icons = { pending: '···', running: '⟳', ok: '✓', done: '✓', error: '✗' };
                const iconEl = el.querySelector('.wizard-step__icon');
                if (iconEl) {
                    iconEl.textContent = icons[state] || '···';
                    // Normalise 'done' → 'ok' for CSS class so existing styles apply
                    const cssState = state === 'done' ? 'ok' : state;
                    iconEl.className = `wizard-step__icon wizard-step__icon--${cssState}`;
                }
                if (detail) {
                    let d = el.querySelector('.wizard-step__detail');
                    if (!d) { d = document.createElement('span'); d.className = 'wizard-step__detail'; el.appendChild(d); }
                    d.textContent = detail;
                }
            }

            function runWizardSetup(serial, package_name) {
                if (wizardStartBtn) { wizardStartBtn.disabled = true; wizardStartBtn.textContent = 'Running…'; }
                const steps = wizardEngine === 'frida' ? FRIDA_STEPS : XPOSED_STEPS;
                steps.forEach(s => updateWizardStep(s.id, 'pending'));
                let setupComplete = false; // flag to silence onerror after done

                const url = wizardEngine === 'frida'
                    ? `/api/runtime/setup-frida-server/${encodeURIComponent(serial)}`
                    : `/api/runtime/setup-xposed/${encodeURIComponent(serial)}?package=${encodeURIComponent(package_name || '')}`;
                setupEventSource = new EventSource(url);

                setupEventSource.addEventListener('step', e => {
                    const d = JSON.parse(e.data);
                    // Backend sends 'message', not 'detail'
                    updateWizardStep(d.step, d.status, d.message || '');
                });
                setupEventSource.addEventListener('done', e => {
                    setupComplete = true;
                    const d = JSON.parse(e.data);
                    addOutput(d.message || `${wizardEngine} setup complete — refreshing device status.`, 'success');
                    setupEventSource.close(); setupEventSource = null;
                    if (wizardStartBtn) { wizardStartBtn.textContent = '✓ Done'; }
                    setTimeout(() => {
                        closeWizard();
                        addOutput('Re-checking device connection…', 'info');
                        // Wait longer for frida-server to fully initialize
                        addOutput('Waiting for frida-server to initialize (this may take a few seconds)...', 'info');
                        setTimeout(() => {
                            startDevicePolling(true);
                        }, 3000);
                    }, 1500);
                });
                setupEventSource.addEventListener('error_event', e => {
                    setupComplete = true; // prevent onerror double-reporting
                    const d = JSON.parse(e.data);
                    addOutput(`Setup error: ${d.message}`, 'error');
                    if (wizardStartBtn) { wizardStartBtn.disabled = false; wizardStartBtn.textContent = 'Retry'; }
                    setupEventSource.close(); setupEventSource = null;
                });
                setupEventSource.onerror = () => {
                    // Ignore if done/error_event already handled completion
                    if (setupComplete) return;
                    // Ignore transient reconnects (readyState 0 = CONNECTING, will auto-retry)
                    if (setupEventSource && setupEventSource.readyState === EventSource.CONNECTING) return;
                    // Stream truly died without a completion event
                    addOutput('SSE connection lost during setup. Check server logs.', 'error');
                    if (wizardStartBtn) { wizardStartBtn.disabled = false; wizardStartBtn.textContent = 'Retry'; }
                    setupEventSource = null;
                };
            }


            // ── New device detected (ADB visible, frida-server not running) ──────────
            function onNewDeviceDetected(dev) {
                selectedSerial = dev.serial;  // always track ADB serial
                toastSerial = dev.serial;
                const eng = getEngine();
                if (eng === 'xposed') {
                    // For Xposed, ADB-only is enough — enable connect
                    xposedReady = true;
                    setDeviceBar('ok', `${dev.model || dev.serial} (ADB — Xposed mode)`);
                    addOutput(`📱 Device ready for Xposed: ${dev.model || dev.serial} [${dev.serial}]`, 'success');
                    _updateConnectBtn();
                    if (continueRuntimeBtn) { continueRuntimeBtn.disabled = false; continueRuntimeBtn.style.opacity = '1'; }
                } else {
                    setDeviceBar('warn', `${dev.model || dev.serial} — frida-server not running`);
                    addOutput(`📱 Device detected: ${dev.model || dev.serial} [${dev.serial}]`, 'info');
                    showToast(dev.serial, dev.model);
                }
            }

            // ── Called when frida-server is confirmed running on USB device ──────────
            function onFridaDeviceReady(dev) {
                fridaReady = true;
                selectedDevice = dev.id;
                // Also store serial for ADB ops
                if (dev.id && !dev.id.startsWith('local') && !dev.id.startsWith('socket')) {
                    knownAdbSerials.add(dev.id);
                    selectedSerial = dev.id;
                }
                _syncRuntimeState();
                hideToast();
                setDeviceBar('ok', `${dev.name} (USB)`);
                addOutput(`✓ Frida device ready: ${dev.name} [${dev.id}]`, 'success');
                if (processLabel) processLabel.style.color = 'var(--text-primary)';
                _updateConnectBtn();
                if (continueRuntimeBtn) { continueRuntimeBtn.disabled = false; continueRuntimeBtn.style.opacity = '1'; }
                startDevicePolling(false); // slow health-check
            }

            // ── Background polling ───────────────────────────────────────────────────
            function startDevicePolling(fast) {
                stopDevicePolling();
                devicePollTimer = setInterval(pollDevices, fast ? 3000 : 8000);
            }
            function stopDevicePolling() {
                if (devicePollTimer) { clearInterval(devicePollTimer); devicePollTimer = null; }
            }

            // Cleanup on page unload to prevent memory leaks
            window.addEventListener('beforeunload', () => {
                stopDevicePolling();
            });

            async function pollDevices() {
                try {
                    const prefResp = await fetch('/api/runtime/preflight');
                    if (!prefResp.ok) return;
                    const data = await prefResp.json();
                    const usbFrida = (data.devices || []).filter(d => d.type === 'usb');

                    if (usbFrida.length > 0) {
                        if (!fridaReady) {
                            console.log('[Poll] Frida device detected:', usbFrida[0]);
                            onFridaDeviceReady(usbFrida[0]);
                        }
                        return;
                    }

                    if (fridaReady) {
                        console.log('[Poll] Frida device lost');
                        fridaReady = false;
                        selectedDevice = null;
                        _syncRuntimeState();
                        knownAdbSerials.clear();
                        const connectBtn = document.getElementById('connect-session-btn');
                        if (connectBtn) { connectBtn.disabled = true; connectBtn.style.opacity = '0.5'; }
                        if (continueRuntimeBtn) { continueRuntimeBtn.disabled = true; continueRuntimeBtn.style.opacity = '0.5'; }
                        addOutput('⚠ Device disconnected (frida-server unreachable).', 'warn');
                        startDevicePolling(true);
                        setDeviceBar('waiting', 'Waiting for device…');
                        return;
                    }

                    const adbResp = await fetch('/api/runtime/adb-devices');
                    if (!adbResp.ok) return;
                    const adbDevices = await adbResp.json();
                    const currentSerials = new Set(adbDevices.map(d => d.serial));

                    for (const dev of adbDevices) {
                        if (!knownAdbSerials.has(dev.serial)) {
                            console.log('[Poll] New ADB device detected:', dev);
                            knownAdbSerials.add(dev.serial);
                            onNewDeviceDetected(dev);
                        }
                    }
                    for (const serial of [...knownAdbSerials]) {
                        if (!currentSerials.has(serial)) {
                            console.log('[Poll] ADB device disconnected:', serial);
                            knownAdbSerials.delete(serial);
                            if (toastSerial === serial) { hideToast(); toastSerial = null; }
                            setDeviceBar('waiting', 'Waiting for device…');
                            addOutput(`Device ${serial} disconnected.`, 'warn');
                        }
                    }
                    if (adbDevices.length > 0)
                        setDeviceBar('warn', `${adbDevices[0].model} — frida-server not running`);

                } catch (e) {
                    console.error('[Poll] Error polling devices:', e);
                }
            }

            // ── Preflight ────────────────────────────────────────────────────────────
            async function runPreflight() {
                try {
                    const r = await fetch('/api/runtime/preflight');
                    if (!r.ok) return;
                    const data = await r.json();

                    // Update preflight row indicators
                    const rows = preflightPanel?.querySelectorAll('[data-preflight-key]') || [];
                    rows.forEach(row => {
                        const key = row.dataset.preflightKey;
                        const val = data[key];
                        const status = val ? 'ok' : 'fail';
                        const sd = row.querySelector('.preflight-status');
                        if (sd) sd.className = `preflight-status preflight-status--${status}`;
                        const sp = row.querySelector('span');
                        if (sp) sp.textContent = val || (key === 'frida_version' ? 'Frida not found' : 'Not ready');
                    });

                    if (data.frida_version) addOutput(`✓ Frida ${data.frida_version} ready on host.`, 'success');

                    const usbFrida = (data.devices || []).filter(d => d.type === 'usb');
                    if (usbFrida.length > 0) {
                        onFridaDeviceReady(usbFrida[0]);
                    } else {
                        setDeviceBar('waiting', 'Waiting for device…');
                        startDevicePolling(true);
                    }
                } catch (e) {
                    addOutput(`Preflight error: ${e.message}`, 'error');
                }
            }

            function updatePreflightRow(key, status, label) {
                const item = preflightPanel?.querySelector(`[data-preflight-key="${key}"]`);
                if (!item) return;
                const sd = item.querySelector('.preflight-status');
                if (sd) sd.className = `preflight-status preflight-status--${status}`;
                const sp = item.querySelector('span');
                if (sp) sp.textContent = label;
            }

            // ── Hooks ────────────────────────────────────────────────────────────────
            async function fetchHooks() {
                try {
                    const r = await fetch('/api/runtime/hooks');
                    window.builtinHooks = await r.json();
                    return window.builtinHooks;
                } catch (e) { return []; }
            }

            function addActiveHook(scriptId, hookName) {
                activeHooks.push({ scriptId, hookName });
                _syncRuntimeState();
                renderActiveHooks();
            }
            function removeActiveHook(scriptId) {
                activeHooks = activeHooks.filter(h => h.scriptId !== scriptId);
                _syncRuntimeState();
                renderActiveHooks();
            }
            function renderActiveHooks() {
                if (!hooksList) return;
                if (activeHooks.length === 0) {
                    hooksList.innerHTML = `<div style="color:var(--text-faint);font-size:12px;text-align:center;padding:var(--sp-4) 0;">
                No hooks injected. ${websocket ? 'Click a hook to inject.' : 'Connect a device first.'}
            </div>`;
                    return;
                }
                hooksList.innerHTML = activeHooks.map(h => `
            <div class="hook-row">
                <span class="hook-row__name">${escapeHtml(h.hookName)}</span>
                <span class="hook-row__arrow">→</span>
                <span class="hook-row__state">active</span>
            </div>`).join('');
            }

            // ── Runtime session ──────────────────────────────────────────────────────
            function disconnectSession() {
                if (!websocket || websocket.readyState !== WebSocket.OPEN) {
                    return;
                }

                const eng = getEngine();
                if (eng === 'frida') {
                    // Send detach message for Frida sessions
                    try {
                        websocket.send(JSON.stringify({ type: 'detach' }));
                    } catch (e) {
                        console.error('[Runtime WS] Failed to send detach:', e);
                    }
                }

                // Close the websocket
                websocket.close();
                addOutput('Session disconnected.', 'warn');
            }

            async function startRuntimeSession() {
                const eng = getEngine();
                const pkg = getSelectedPackage();

                // Validate package
                if (!pkg || pkg.startsWith('No ') || pkg.startsWith('Select')) {
                    addOutput('✗ No target package. Use "⟳ Fetch" to load apps from device, then select one.', 'error');
                    return;
                }

                // Auto-disconnect if there's an active session for a different package
                if (websocket && websocket.readyState === WebSocket.OPEN) {
                    if (selectedPackage && selectedPackage !== pkg) {
                        addOutput(`⚠ Switching app from ${escapeHtml(selectedPackage)} to ${escapeHtml(pkg)} — disconnecting previous session...`, 'warn');
                        disconnectSession();
                        // Wait for disconnect to complete before connecting to new app
                        await new Promise(resolve => setTimeout(resolve, 500));
                    } else {
                        addOutput('⚠ Session already active for this package.', 'warn');
                        return;
                    }
                }

                selectedPackage = pkg;

                if (eng === 'xposed') {
                    // Xposed path: ADB serial is enough
                    const serial = selectedSerial || toastSerial;
                    if (!serial) {
                        addOutput('✗ No ADB device. Connect phone via USB first.', 'error'); return;
                    }
                    addOutput(`▶ Starting Xposed logcat stream for ${escapeHtml(pkg)}…`, 'info');
                    connectWebSocket(serial, pkg);
                } else {
                    // Frida path: Frida device ID required
                    if (!selectedDevice) {
                        addOutput('✗ No Frida device. Ensure frida-server is running and device is connected.', 'error');
                        return;
                    }
                    addOutput(`▶ Connecting Frida to ${escapeHtml(pkg)}…`, 'info');
                    connectWebSocket(selectedDevice, pkg);
                }
            }

            function connectWebSocket(deviceOrSerial, packageName) {
                const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
                const eng = getEngine();
                // Route to correct WebSocket endpoint based on engine
                const wsPath = eng === 'xposed'
                    ? `/api/runtime/ws/xposed/${encodeURIComponent(deviceOrSerial)}/${encodeURIComponent(packageName)}`
                    : `/api/runtime/ws/${encodeURIComponent(deviceOrSerial)}/${encodeURIComponent(packageName)}`;
                const wsUrl = `${proto}//${location.host}${wsPath}`;
                websocket = new WebSocket(wsUrl);
                const connectBtn = document.getElementById('connect-session-btn');

                websocket.onopen = () => {
                _syncRuntimeState();
                    if (eng === 'xposed') {
                        // Xposed: WS is open, logcat stream starts automatically on server side
                        if (connectBtn) { connectBtn.textContent = '✕ Disconnect'; connectBtn.style.opacity = '1'; connectBtn.disabled = false; }
                        // Show TrustMeAlready hooks as always-active
                        addActiveHook('logcat', 'TrustMeAlready (SSL Bypass)');
                    } else {
                        // Frida: open → send attach command
                        addOutput('✓ Session connected. Attaching to process…', 'success');
                        if (connectBtn) { connectBtn.textContent = '✕ Disconnect'; connectBtn.style.opacity = '1'; connectBtn.disabled = false; }
                        websocket.send(JSON.stringify({ type: 'attach' }));
                    }
                };
                websocket.onmessage = (e) => { try { handleWsMessage(JSON.parse(e.data)); } catch (_) { } };
                websocket.onerror = () => {
                    if (eng === 'xposed') {
                        addOutput('✗ WebSocket error. Is the device connected via ADB?', 'error');
                    } else {
                        addOutput('✗ WebSocket error. Is frida-server running on the device?', 'error');
                    }
                };
                websocket.onclose = () => {
                    addOutput('Session disconnected.', 'warn');
                    addLog('Session disconnected.', 'info');
                    websocket = null;
                    pendingScript = null;
                    activeHooks = activeHooks.filter(h => h.scriptId !== 'logcat');
                    _syncRuntimeState();
                    renderActiveHooks();
                    // Clear logs on disconnect
                    if (logsStream) {
                        logsStream.innerHTML = '<div class="log-line" style="color:var(--text-faint);font-size:12px;">No runtime logs. Connect a session to see live script output.</div>';
                    }
                    // Re-evaluate connect button state based on engine readiness
                    _updateConnectBtn();
                    if (connectBtn) connectBtn.textContent = '▶ Connect';
                };
            }

            function handleWsMessage(msg) {
                switch (msg.type) {
                    case 'connected':
                        // Xposed logcat stream started
                        addOutput(`✓ ${msg.payload || 'Xposed logcat stream connected.'}`, 'success');
                        addLog(msg.payload || 'Xposed logcat stream connected.', 'info');
                        activeSession = 'xposed-logcat';
                        break;
                    case 'attached':
                        // Frida: session attached
                        activeSession = msg.session_id;
                        addOutput(`✓ Attached to session [${msg.session_id}]`, 'success');
                        addLog(`Attached to session [${msg.session_id}]`, 'info');
                        // Flush any script/hook that was queued before attach completed
                        if (pendingScript) {
                            const s = pendingScript;
                            pendingScript = null;
                            if (s && typeof s === 'object' && s.__hook_name) {
                                addOutput(`Injecting queued hook: ${s.__hook_name}…`, 'info');
                                websocket?.send(JSON.stringify({ type: 'inject', hook_name: s.__hook_name }));
                            } else {
                                addOutput('Injecting queued script…', 'info');
                                websocket?.send(JSON.stringify({ type: 'inject', script: s }));
                            }
                        }
                        break;
                    case 'injected':
                        addOutput(`✓ Script injected [${msg.hook || 'custom'}]`, 'success');
                        addLog(`Script injected [${msg.hook || 'custom'}]`, 'info');
                        addActiveHook(msg.script_id, msg.hook || 'custom');
                        break;
                    case 'output':
                        addOutput(msg.payload, 'info');
                        addLog(msg.payload, 'info');
                        break;
                    case 'warn':
                        addOutput(msg.payload, 'warn');
                        addLog(msg.payload, 'warn');
                        break;
                    case 'error':
                        addOutput(`✗ ${msg.payload}`, 'error');
                        addLog(msg.payload, 'error');
                        if (msg.payload.startsWith('Attach failed') || msg.payload.startsWith('Spawn failed')) {
                            // Close the deadlocked websocket so the next action triggers a fresh reconnect
                            websocket?.close();
                            activeSession = null;
                        }
                        break;
                    case 'detached':
                        addOutput('Session detached.', 'warn');
                        addLog('Session detached.', 'info');
                        activeSession = null;
                        // Clear logs on detach
                        if (logsStream) {
                            logsStream.innerHTML = '<div class="log-line" style="color:var(--text-faint);font-size:12px;">No runtime logs. Connect a session to see live script output.</div>';
                        }
                        break;
                    case 'ping': break; // keepalive

                    case 'ai_pivot_start': {
                        // Show amber banner in output panel; notify AI drawer
                        const bannerLine = document.createElement('div');
                        bannerLine.className = 'output-line output-line--ai-pivot';
                        const now = new Date();
                        const ts = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}:${String(now.getSeconds()).padStart(2,'0')}`;
                        bannerLine.innerHTML = `<span class="output-line__ts">[${ts}]</span> <span class="output-line__msg output-line__msg--pivot">🤖 AI analyzing error — pivoting strategy…</span>`;
                        outputStream?.appendChild(bannerLine);
                        outputStream && (outputStream.scrollTop = outputStream.scrollHeight);
                        pivotBannerEl = bannerLine;
                        if (!window._irvesPivotBridge) {
                            console.error('[Runtime WS] _irvesPivotBridge not registered — runtime_ai_partner.js may not have loaded');
                            addOutput('⚠ AI pivot bridge not available. Ensure runtime_ai_partner.js loaded.', 'warn');
                        } else {
                            window._irvesPivotBridge.start(msg.payload || '');
                        }
                        break;
                    }
                    case 'ai_pivot_token':
                        window._irvesPivotBridge?.token(msg.payload || '');
                        break;
                    case 'ai_pivot_done': {
                        if (pivotBannerEl) {
                            pivotBannerEl.querySelector('.output-line__msg--pivot').textContent = '✓ AI pivot complete — see AI drawer →';
                            pivotBannerEl.classList.add('output-line--ai-pivot-done');
                        }
                        pivotBannerEl = null;
                        window._irvesPivotBridge?.done(msg.payload || '');
                        break;
                    }
                    case 'ai_pivot_error': {
                        if (pivotBannerEl) {
                            pivotBannerEl.querySelector('.output-line__msg--pivot').textContent = `✗ AI pivot error: ${msg.payload || 'unknown'}`;
                            pivotBannerEl.classList.add('output-line--ai-pivot-error');
                        }
                        pivotBannerEl = null;
                        window._irvesPivotBridge?.error(msg.payload || '');
                        break;
                    }
                }
            }


            // ── Script execution ─────────────────────────────────────────────────────
            function runFridaScript() {
                const eng = getEngine();
                if (eng === 'xposed') {
                    addOutput(
                        '⚠ Xposed mode uses always-on hooks via TrustMeAlready module. '
                        + 'Switch engine to Frida to run custom scripts, or use "Guided Hooks" for supported bypass hooks.',
                        'warn'
                    );
                    return;
                }
                const script = scriptEditor?.value?.trim();
                if (!script) { addOutput('⚠ Enter a Frida script first.', 'warn'); return; }

                // Already connected → inject directly
                if (websocket && websocket.readyState === WebSocket.OPEN) {
                    addOutput('Injecting script…', 'info');
                    websocket.send(JSON.stringify({ type: 'inject', script }));
                    return;
                }

                // Not connected yet — validate then auto-connect
                if (!selectedDevice) {
                    addOutput('✗ No device. Ensure frida-server is running and device is connected.', 'error'); return;
                }
                const pkg = getSelectedPackage();
                if (!pkg || pkg.startsWith('No ') || pkg.startsWith('Select')) {
                    addOutput('✗ No target package. Use "⟳ Fetch" to load apps, then select one.', 'error'); return;
                }

                addOutput('❯ No active session — auto-connecting…', 'info');
                selectedPackage = pkg;
                pendingScript = script;
                connectWebSocket(selectedDevice, selectedPackage);
            }

            function injectHook(hookName) {
                const eng = getEngine();

                if (eng === 'xposed') {
                    // Xposed: hooks are always-on via TrustMeAlready module.
                    // Show user that they need to check logcat for output.
                    if (!websocket || websocket.readyState !== WebSocket.OPEN) {
                        addOutput(
                            `ℹ Xposed: "${hookName}" is always active when the app is launched. `
                            + 'Connect the logcat stream to see live output.',
                            'info'
                        );
                        // Auto-start logcat stream if device available
                        const serial = selectedSerial || toastSerial;
                        const pkg = getSelectedPackage();
                        if (serial && pkg && !pkg.startsWith('No ') && !pkg.startsWith('Select')) {
                            selectedPackage = pkg;
                            connectWebSocket(serial, pkg);
                        }
                    } else {
                        addOutput(
                            `ℹ Xposed: "${hookName}" is always active. Output visible in logcat stream above.`,
                            'info'
                        );
                    }
                    return;
                }

                // Frida path: inject hook script via WebSocket
                if (websocket && websocket.readyState === WebSocket.OPEN) {
                    addOutput(`Injecting hook: ${hookName}`, 'info');
                    websocket.send(JSON.stringify({ type: 'inject', hook_name: hookName }));
                    return;
                }
                // Not connected — auto-connect with hook queued
                if (!selectedDevice) {
                    addOutput('✗ No device. Ensure frida-server is running and device is connected.', 'error'); return;
                }
                const pkg = getSelectedPackage();
                if (!pkg || pkg.startsWith('No ') || pkg.startsWith('Select')) {
                    addOutput('✗ No target package. Use "⟳ Fetch" to load apps, then select one.', 'error'); return;
                }
                addOutput(`❯ No active session — auto-connecting to inject hook: ${hookName}…`, 'info');
                selectedPackage = pkg;
                pendingScript = { __hook_name: hookName };
                connectWebSocket(selectedDevice, selectedPackage);
            }

            function saveCurrentHook() {
                const script = scriptEditor?.value?.trim();
                if (!script) { window.irves?.showToast('Enter a script to save.'); return; }
                const name = prompt('Hook name:');
                if (!name) return;
                const saved = JSON.parse(localStorage.getItem('irves_custom_hooks') || '[]');
                saved.push({ name, script, created: new Date().toISOString() });
                localStorage.setItem('irves_custom_hooks', JSON.stringify(saved));
                window.irves?.showToast(`Hook "${name}" saved.`);
            }

            async function showGuidedHooks() {
                const hooks = await fetchHooks();
                if (!hooks?.length) { window.irves?.showToast('No built-in hooks.'); return; }

                const grouped = {};
                hooks.forEach(h => { if (!grouped[h.category]) grouped[h.category] = []; grouped[h.category].push(h); });

                const riskColors = { high: '#ef4444', medium: '#f59e0b', low: '#22c55e' };
                const riskLabels = { high: 'HIGH IMPACT', medium: 'MEDIUM', low: 'LOW IMPACT' };

                const categoryHtml = Object.entries(grouped).map(([cat, catHooks]) => `
            <div style="margin-bottom:20px;">
                <div style="font-size:10px;font-weight:700;letter-spacing:0.08em;color:var(--text-faint);text-transform:uppercase;margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid var(--border);">${escapeHtml(cat)}</div>
                ${catHooks.map(h => `
                    <div class="gh-row" data-hook="${escapeHtml(h.name)}" style="display:flex;align-items:flex-start;gap:12px;padding:12px;border-radius:7px;cursor:pointer;transition:background 0.15s;margin-bottom:4px;"
                        onmouseover="this.style.background='var(--surface-raised)'" onmouseout="this.style.background='transparent'">
                        <div style="flex:1;min-width:0;">
                            <div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;flex-wrap:wrap;">
                                <span style="font-size:13px;font-weight:600;color:var(--text-primary);">${escapeHtml(h.label || h.name)}</span>
                                <span style="font-size:9px;font-weight:700;padding:2px 6px;border-radius:3px;background:${riskColors[h.risk] || '#6366f1'}22;color:${riskColors[h.risk] || '#6366f1'};letter-spacing:0.05em;">${riskLabels[h.risk] || 'MEDIUM'}</span>
                                ${(h.tags || []).map(t => `<span style="font-size:10px;padding:1px 5px;border-radius:3px;background:var(--surface-raised);color:var(--text-muted);font-family:var(--font-mono);">${escapeHtml(t)}</span>`).join('')}
                            </div>
                            <div style="font-size:12px;color:var(--text-muted);line-height:1.5;">${escapeHtml(h.description)}</div>
                        </div>
                        <div style="display:flex;gap:6px;flex-shrink:0;margin-top:2px;">
                            <button class="btn btn--ghost btn--sm gh-view-btn" data-hook="${escapeHtml(h.name)}"
                                style="font-size:11px;padding:4px 10px;" title="View script in editor">
                                View
                            </button>
                            <button class="btn btn--primary btn--sm gh-inject-btn" data-hook="${escapeHtml(h.name)}"
                                style="font-size:11px;padding:4px 10px;"
                                ${!websocket ? 'disabled title="Connect a session first"' : ''}>
                                Inject
                            </button>
                        </div>
                    </div>`).join('')}
            </div>`).join('');

                const modal = document.createElement('div');
                modal.id = 'guided-hooks-modal';
                modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.72);display:flex;align-items:center;justify-content:center;z-index:1000;backdrop-filter:blur(3px);';
                modal.innerHTML = `
            <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;width:620px;max-width:95vw;max-height:85vh;display:flex;flex-direction:column;box-shadow:0 24px 64px rgba(0,0,0,0.55);">
                <div style="display:flex;align-items:center;justify-content:space-between;padding:20px 24px 0;">
                    <div>
                        <h3 style="margin:0 0 3px;font-size:15px;">Must-Have Hooks</h3>
                        <p style="margin:0;font-size:12px;color:var(--text-muted);">${hooks.length} built-in hooks — click Inject to activate on the running session</p>
                    </div>
                    <button class="btn btn--ghost btn--sm" id="gh-close-btn">✕</button>
                </div>
                <div style="flex:1;overflow-y:auto;padding:16px 24px 24px;">
                    ${!websocket ? `<div style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);border-radius:6px;padding:10px 14px;font-size:12px;color:var(--critical);margin-bottom:16px;">⚠ No active session. Start a runtime session first, then inject hooks.</div>` : ''}
                    ${categoryHtml}
                </div>
            </div>`;
                document.body.appendChild(modal);
                modal.querySelector('#gh-close-btn').onclick = () => modal.remove();
                modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
                modal.querySelectorAll('.gh-view-btn').forEach(btn => {
                    btn.onclick = async (e) => {
                        e.stopPropagation();
                        const hookName = btn.dataset.hook;
                        console.log('[View] Clicked View for:', hookName);
                        console.log('[View] scriptEditor exists:', !!scriptEditor);
                        try {
                            const r = await fetch(`/api/runtime/hooks/${encodeURIComponent(hookName)}`);
                            console.log('[View] Fetch status:', r.status, r.ok);
                            if (r.ok) {
                                const data = await r.json();
                                console.log('[View] Response data keys:', Object.keys(data));
                                console.log('[View] script length:', data.script ? data.script.length : 'null');
                                if (data.script && scriptEditor) {
                                    modal.remove();
                                    scriptEditor.value = data.script;
                                    console.log('[View] Set scriptEditor.value, length:', scriptEditor.value.length);
                                    scriptEditor.dispatchEvent(new Event('input'));
                                    scriptEditor.focus();
                                    const editorPanel = document.getElementById('script-editor-panel');
                                    if (editorPanel) editorPanel.scrollIntoView({ behavior: 'smooth', block: 'center' });
                                    addOutput(`\u25b6 Loaded "${hookName}" into script editor.`, 'info');
                                } else {
                                    console.error('[View] scriptEditor or data.script is falsy');
                                    addOutput(`Hook "${hookName}" script is empty.`, 'error');
                                }
                            } else {
                                console.error('[View] Fetch failed:', r.status);
                                addOutput(`Failed to load hook script: ${hookName} (HTTP ${r.status})`, 'error');
                            }
                        } catch (err) {
                            console.error('[View] Fetch error:', err);
                            addOutput(`Error loading hook: ${err}`, 'error');
                        }
                    };
                });
                modal.querySelectorAll('.gh-inject-btn').forEach(btn => {
                    btn.onclick = (e) => {
                        e.stopPropagation();
                        injectHook(btn.dataset.hook);
                        btn.textContent = '✓ Injected';
                        btn.disabled = true;
                        btn.style.opacity = '0.6';
                    };
                });
                modal.querySelectorAll('.gh-row').forEach(row => {
                    row.onclick = (e) => {
                        if (e.target.closest('.gh-inject-btn') || e.target.closest('.gh-view-btn')) return;
                        if (!websocket) return;
                        injectHook(row.dataset.hook);
                        modal.remove();
                    };
                });
            }

            // ── Initialize ───────────────────────────────────────────────────────────
            fetchHooks();
            renderActiveHooks();
            runPreflight();
            _syncRuntimeState();

        })();
