import re
with open('/home/orgilbold/Documents/Irves/backend/templates/screens/dashboard.html', 'r') as f:
    # Just to get the exact paths if needed...
    pass

new_scan_raw = """{% extends "base.html" %}
{% block title %}New Scan — IRVES{% endblock %}

{% block content %}
<div class="page" style="max-width: 1400px;">
    <div class="page-header">
        <div>
            <h1 class="page-header__title">New Scan</h1>
            <p class="page-header__subtitle">Configure target and execute scan</p>
        </div>
    </div>

    <div style="display: grid; grid-template-columns: 460px 1fr; gap: var(--sp-8); align-items: start;">
        
        <!-- Left: Configuration -->
        <form id="new-scan-form" style="width: 100%; display:flex; flex-direction:column; gap: var(--sp-6);"
        onsubmit="startScan(event)">
        <!-- Target drop zone -->
        <div class="field">
            <label class="field__label">Target File</label>

            <!-- Hidden real file input -->
            <input type="file" id="file-input" name="file" accept=".apk,.ipa,.exe,.msi,.dmg,.deb,.rpm,.appimage"
                style="display:none;" aria-label="Select target file" />

            <!-- Drop zone -->
            <div id="drop-zone" role="button" tabindex="0"
                aria-label="Drop APK, IPA or other binary here, or click to browse" style="
                    display:flex; flex-direction:column; align-items:center; justify-content:center;
                    gap:var(--sp-3); padding:var(--sp-6) var(--sp-4);
                    background:var(--surface-raised); border:1.5px dashed var(--border);
                    border-radius:var(--radius); cursor:pointer;
                    transition:border-color var(--transition), background var(--transition);
                    min-height:110px; text-align:center;
                ">
                <!-- Upload icon -->
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" aria-hidden="true" id="drop-icon"
                    style="color:var(--text-muted);">
                    <path d="M12 16V8M12 8l-3 3M12 8l3 3" stroke="currentColor" stroke-width="1.5"
                        stroke-linecap="round" stroke-linejoin="round" />
                    <path d="M3 16v2a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-2" stroke="currentColor" stroke-width="1.5"
                        stroke-linecap="round" />
                </svg>

                <div>
                    <div id="drop-label" style="font-size:13px;color:var(--text-primary);font-weight:500;">Drop file
                        here or <span style="color:var(--accent);text-decoration:underline;">browse</span></div>
                    <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">APK &middot; IPA &middot; EXE
                        &middot; DMG &middot; DEB</div>
                </div>

                <!-- Chosen file name shown here -->
                <div id="drop-file-info"
                    style="display:none;font-family:var(--font-mono);font-size:12px;color:var(--accent);"></div>
            </div>

            <!-- Upload progress bar (hidden until upload starts) -->
            <div id="upload-progress-wrap" style="display:none;margin-top:var(--sp-2);">
                <div
                    style="display:flex;justify-content:space-between;font-size:11px;color:var(--text-muted);margin-bottom:4px;">
                    <span>Uploading…</span>
                    <span id="upload-pct">0%</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-bar__fill" id="upload-fill" style="width:0%;"></div>
                </div>
            </div>

            <input type="hidden" name="target" id="target-value" value="" />
            <input type="hidden" id="uploaded-filename" value="" />
        </div>

        <!-- Platform -->
        <div class="field">
            <label class="field__label" for="platform-select">Platform</label>
            <select class="field__select" name="platform" id="platform-select">
                <option value="android">Android</option>
                <option value="ios">iOS</option>
                <option value="web">Web</option>
                <option value="desktop">Desktop</option>
            </select>
        </div>

        <!-- Scan Profile -->
        <div class="field">
            <div class="field__label">Scan Profile</div>
            <div class="radio-group" id="scan-profile-group" role="radiogroup" aria-label="Scan profile">

                <label class="radio-option selected" id="profile-full-label">
                    <input type="radio" name="profile" value="full" checked id="profile-full" />
                    <div class="radio-option__dot" aria-hidden="true"></div>
                    <div>
                        <div class="radio-option__text">Full Scan</div>
                        <div class="radio-option__desc">All tools, complete pipeline</div>
                    </div>
                </label>

                <label class="radio-option" id="profile-quick-label">
                    <input type="radio" name="profile" value="quick" id="profile-quick" />
                    <div class="radio-option__dot" aria-hidden="true"></div>
                    <div>
                        <div class="radio-option__text">Quick Scan</div>
                        <div class="radio-option__desc">Static only — no device needed</div>
                    </div>
                </label>

                <label class="radio-option" id="profile-runtime-label">
                    <input type="radio" name="profile" value="runtime" id="profile-runtime" />
                    <div class="radio-option__dot" aria-hidden="true"></div>
                    <div>
                        <div class="radio-option__text">Runtime Only</div>
                        <div class="radio-option__desc">Opens Frida Runtime Workspace — physical device required</div>
                    </div>
                </label>

                <label class="radio-option" id="profile-custom-label">
                    <input type="radio" name="profile" value="custom" id="profile-custom" />
                    <div class="radio-option__dot" aria-hidden="true"></div>
                    <div>
                        <div class="radio-option__text">Custom</div>
                        <div class="radio-option__desc">Select tools manually</div>
                    </div>
                </label>
            </div>
        </div>

        <!-- Custom Tool Selection Panel (Hidden by default) -->
        <div id="custom-tools-panel" style="display:none; margin-bottom:var(--sp-4);">
            <div class="field">
                <div class="field__label">Select Analysis Tools</div>
                <div style="display:flex; flex-direction:column; gap:var(--sp-2); padding:var(--sp-3); background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:var(--radius);">
                    {% for tool_val, tool_label in [
                        ("apktool", "APK Tool (Decompilation)"),
                        ("jadx", "JADX (Java Analysis)"),
                        ("frida", "Frida (Runtime Hooks)"),
                        ("mitmproxy", "mitmproxy (Traffic Capture)"),
                        ("custom", "Custom Analyzers")
                    ] %}
                    <label style="display:flex; align-items:center; gap:var(--sp-2); cursor:pointer; font-size:13px; color:var(--text-primary);">
                        <input type="checkbox" name="tools" value="{{ tool_val }}" {% if tool_val
                            not in ["sbom"] %}checked{% endif %} style="accent-color:var(--accent);" />
                        {{ tool_label }}
                    </label>
                    {% endfor %}
                </div>
            </div>
        </div>

        <!-- Project name -->
        <div class="field">
            <label class="field__label" for="project-name-input">Project Name</label>
            <input type="text" class="field__input" name="project_name" id="project-name-input"
                placeholder="e.g. BankApp v2.3" autocomplete="off" required />
        </div>

        <!-- Submit -->
        <div style="display:flex; justify-content:flex-end; padding-top:var(--sp-2);">
            <button type="submit" class="btn btn--primary btn--lg" id="begin-scan-btn">
                Begin Scan
                <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                    <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"
                        stroke-linejoin="round" />
                </svg>
            </button>
        </div>

        <div id="scan-response" style="font-size:13px;color:var(--critical);margin-top:var(--sp-2);"></div>
    </form>

        <!-- Right: Live Panel -->
        <div style="display:flex; flex-direction: column; gap: var(--sp-6);">
            
            <div id="live-scan-panel" style="display:none; flex-direction: column; gap: var(--sp-6);">
                <div style="display:flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: var(--sp-4);">
                    <div>
                        <h2 class="page-header__title" id="live-scan-title" style="font-size: 18px; margin-bottom: 4px;">Scan in Progress</h2>
                        <p class="page-header__subtitle" id="scan-status-subtitle" style="font-size: 13px;">Initializing pipeline...</p>
                    </div>
                    <div style="display:flex; gap: var(--sp-3);">
                        <button type="button" class="btn btn--danger btn--sm" id="cancel-scan-btn" onclick="cancelScan()" style="display:none;">Cancel</button>
                        <a href="#" class="btn btn--primary" id="view-results-btn" style="opacity:0.4;pointer-events:none;">
                            View Full Results
                            <svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                                <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
                            </svg>
                        </a>
                    </div>
                </div>

                <!-- LIVE SCAN COMPONENTS CONTENT -->
                <div class="pipeline-section" id="sse-pipeline">

                    <!-- Progress -->
                    <div class="card" style="margin-bottom:var(--sp-6);">
                        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:var(--sp-3);">
                            <span style="font-family:var(--font-mono);font-size:13px;color:var(--accent);"
                                id="progress-pct">0%</span>
                            <span style="font-size:12px;color:var(--text-muted);" id="progress-eta">Running</span>
                        </div>
                        <div class="progress-bar" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">
                            <div class="progress-bar__fill" id="progress-fill" style="width:0%;"></div>
                        </div>
                    </div>

                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--sp-6);">

                        <!-- Pipeline -->
                        <div>
                            <div class="panel">
                                <div class="panel__header">Pipeline</div>
                                <div style="padding:var(--sp-4);" id="pipeline-list">

                                    {% set stages = [
                                    ("manifest", "queued", "Manifest Checks", "Waiting..."),
                                    ("pattern_scan", "queued", "Pattern Scan", "Waiting..."),
                                    ("bytecode", "queued", "Bytecode Analysis","Waiting..."),
                                    ("ai", "queued", "AI Auto-Triage", "Waiting..."),
                                    ("complete", "queued", "Finalizing", "Waiting...")
                                    ] %}

                                    {% for stage_id, state, name, detail in stages %}
                                    <div class="pipeline-step pipeline-step--{{ state }}" id="stage-{{ stage_id }}">
                                        <div class="pipeline-step__status-icon" aria-label="{{ state }}">
                                            <svg width="15" height="15" viewBox="0 0 16 16" fill="none">
                                                <circle cx="8" cy="8" r="6.5" stroke="currentColor" stroke-width="1.25"
                                                    opacity="0.3" />
                                            </svg>
                                        </div>
                                        <div class="pipeline-step__name">{{ name }}</div>
                                        <div class="pipeline-step__detail" id="stage-{{ stage_id }}-detail">{{ detail }}</div>
                                    </div>
                                    {% endfor %}

                                </div>
                            </div>
                        </div>

                        <!-- Live findings -->
                        <div>
                            <div class="panel" style="height:100%;">
                                <div class="panel__header">
                                    Live Findings
                                    <span id="live-finding-count" style="font-family:var(--font-mono);color:var(--accent);">0</span>
                                </div>
                                <div class="panel__body" id="live-findings-list">
                                    <!-- Findings injected here via SSE and JS -->
                                    <div style="padding:var(--sp-4);color:var(--text-muted);font-size:14px;text-align:center;"
                                        id="findings-placeholder">
                                        Waiting for findings...
                                    </div>
                                </div>
                            </div>
                        </div>

                    </div>
                </div>

                <div id="runtime-handoff-panel" style="display:none; margin-top: var(--sp-6);">
                    <div class="card" style="
                        border: 1.5px solid var(--accent);
                        background: rgba(99,102,241,0.06);
                        padding: var(--sp-6);
                        display: flex;
                        flex-direction: column;
                        gap: var(--sp-4);
                    ">
                        <div style="display:flex; align-items:center; gap: var(--sp-3);">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true" style="color:var(--accent);flex-shrink:0">
                                <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.5" fill="rgba(99,102,241,0.15)"/>
                                <path d="M8 12l3 3 5-5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                            <div>
                                <div style="font-weight:600; font-size:14px; color:var(--text-primary);">Static Analysis Complete</div>
                                <div style="font-size:12px; color:var(--text-muted); margin-top:2px;" id="handoff-summary">Full Scan — Phase 1 done. Phase 2: Runtime Instrumentation is ready.</div>
                            </div>
                        </div>
                        <div style="font-size:13px; color:var(--text-muted); line-height:1.6; padding-left: 32px;">
                            The static analysis phase has finished. You can now proceed to the
                            <strong style="color:var(--text-primary);">Runtime Workspace</strong> to instrument
                            the app using Frida or Xposed. Select which functions, APIs, or errors to examine.
                        </div>
                        <div style="display:flex; align-items:center; gap:var(--sp-3); padding-left:32px;">
                            <button class="btn btn--primary" id="proceed-runtime-btn">
                                ▶ Proceed to Runtime Instrumentation
                                <svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true" style="margin-left:4px">
                                    <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
                                </svg>
                            </button>
                            <a id="skip-runtime-link" href="#" style="font-size:12px; color:var(--text-muted);text-decoration:underline;">Skip — view results only</a>
                        </div>
                    </div>
                </div>

            </div>
            
            <!-- Placeholder when right side is empty -->
            <div id="live-scan-placeholder" style="display:flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; min-height: 400px; border: 1.5px dashed var(--border); border-radius: var(--radius); background: var(--surface-raised);">
                <div style="color: var(--text-muted); font-size: 13px; text-align: center;">
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" aria-hidden="true" style="margin-bottom: var(--sp-3); opacity: 0.5;">
                        <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.5"/>
                        <path d="M12 8v4l3 3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
                    </svg><br>
                    Configure profile & Start scan<br>to view live analysis here.
                </div>
            </div>

        </div>

    </div>
</div>

<script>
    // Make variables global to handle the unified screen state
    let _scanId = null;
    let _projectId = null;
    let _isFullScan = true;
    let _evtSource = null;

    async function startScan(e) {
        e.preventDefault();
        const btn = document.getElementById('begin-scan-btn');
        const errBox = document.getElementById('scan-response');
        btn.disabled = true;
        btn.textContent = 'Starting…';
        errBox.textContent = '';

        const platform = document.getElementById('platform-select').value;
        const projectName = document.getElementById('project-name-input').value.trim();
        const profile = document.querySelector('[name="profile"]:checked')?.value || 'full';
        const targetValue = document.getElementById('target-value').value.trim();
        const uploadedFile = document.getElementById('uploaded-filename');
        const existingProjectId = uploadedFile?.dataset?.projectId || null;

        if (profile !== 'runtime' && !targetValue) {
            errBox.textContent = '✗ Please upload or select a target file first.';
            btn.disabled = false;
            btn.innerHTML = 'Begin Scan <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" /></svg>';
            return;
        }

        try {
            let projectId = existingProjectId;

            if (!projectId) {
                const projRes = await fetch('/api/scan/projects', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        name: projectName || 'Unnamed Project',
                        platform: platform,
                        target_path: targetValue || null,
                        description: `${platform} scan — ${profile} profile`,
                    }),
                });
                if (!projRes.ok) {
                    let errStr = 'Failed to create project';
                    try {
                        const err = await projRes.json();
                        errStr = err.detail || errStr;
                    } catch (e) { errStr = await projRes.text(); }
                    throw new Error(errStr);
                }
                const project = await projRes.json();
                projectId = project.id;
            }

            if (profile === 'runtime') {
                const url = `/runtime?project=${projectId}`;
                if (window.parent !== window) {
                    window.parent.postMessage({ type: 'navigate', href: url }, '*');
                } else {
                    window.location.href = url;
                }
                return;
            }

            const customTools = Array.from(document.querySelectorAll('input[name="tools"]:checked')).map(el => el.value);
            const scanRes = await fetch(`/api/scan/${platform}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    project_id: projectId,
                    profile: profile,
                    custom_tools: customTools,
                }),
            });
            if (!scanRes.ok) {
                let errStr = 'Failed to start scan';
                try {
                    const err = await scanRes.json();
                    errStr = err.detail || errStr;
                } catch (e) { errStr = await scanRes.text(); }
                throw new Error(errStr);
            }
            const scan = await scanRes.json();

            // Reveal Live Scan inline panel
            _scanId = scan.id;
            _projectId = projectId;
            _isFullScan = (profile === 'full');
            
            document.getElementById("live-scan-placeholder").style.display = "none";
            document.getElementById("live-scan-panel").style.display = "flex";
            document.getElementById("cancel-scan-btn").style.display = "inline-flex";
            
            // Start listening
            startSSE();
        } catch (err) {
            errBox.textContent = '✗ ' + err.message;
            btn.disabled = false;
            btn.innerHTML = 'Begin Scan <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" /></svg>';
        }
    }

    (function () {
        const dropZone = document.getElementById('drop-zone');
        const fileInput = document.getElementById('file-input');
        const dropLabel = document.getElementById('drop-label');
        const dropFileInfo = document.getElementById('drop-file-info');
        const targetValue = document.getElementById('target-value');
        const uploadedFilename = document.getElementById('uploaded-filename');
        const progressWrap = document.getElementById('upload-progress-wrap');
        const uploadFill = document.getElementById('upload-fill');
        const uploadPct = document.getElementById('upload-pct');
        const platformSelect = document.getElementById('platform-select');
        const nameInput = document.getElementById('project-name-input');

        const ALLOWED_EXT = ['.apk', '.ipa', '.exe', '.msi', '.dmg', '.deb', '.rpm', '.appimage'];
        const MAX_SIZE_MB = 500;

        function detectPlatform(filename) {
            const lower = filename.toLowerCase();
            if (lower.endsWith('.apk')) return 'android';
            if (lower.endsWith('.ipa')) return 'ios';
            if (['.exe', '.msi', '.dmg', '.deb', '.rpm', '.appimage'].some(e => lower.endsWith(e))) return 'desktop';
            return null;
        }

        function setDropZoneActive(active) {
            dropZone.style.borderColor = active ? 'var(--accent)' : 'var(--border)';
            dropZone.style.background = active ? 'rgba(var(--accent-rgb, 99,102,241),0.07)' : 'var(--surface-raised)';
        }

        function setDropZoneError(msg) {
            dropLabel.innerHTML = `<span style="color:var(--critical);">✗ ${msg}</span>`;
            dropFileInfo.style.display = 'none';
            setDropZoneActive(false);
        }

        async function handleFile(file) {
            const ext = '.' + file.name.split('.').pop().toLowerCase();
            if (!ALLOWED_EXT.includes(ext)) {
                setDropZoneError(`Unsupported file type: ${ext}`);
                return;
            }
            if (file.size > MAX_SIZE_MB * 1024 * 1024) {
                setDropZoneError(`File too large (max ${MAX_SIZE_MB} MB)`);
                return;
            }

            dropLabel.innerHTML = `<span style="color:var(--text-muted);">Selected:</span>`;
            dropFileInfo.textContent = file.name + ' (' + (file.size / 1024 / 1024).toFixed(1) + ' MB)';
            dropFileInfo.style.display = 'block';
            setDropZoneActive(true);

            const detectedPlatform = detectPlatform(file.name);
            if (detectedPlatform) platformSelect.value = detectedPlatform;

            if (!nameInput.value.trim()) {
                nameInput.value = file.name.replace(/\.[^.]+$/, '');
            }

            progressWrap.style.display = 'block';
            uploadFill.style.width = '0%';
            uploadPct.textContent = '0%';

            const formData = new FormData();
            formData.append('file', file);

            try {
                await new Promise((resolve, reject) => {
                    const xhr = new XMLHttpRequest();
                    xhr.open('POST', '/api/scan/upload');

                    xhr.upload.addEventListener('progress', (e) => {
                        if (e.lengthComputable) {
                            const pct = Math.round((e.loaded / e.total) * 100);
                            uploadFill.style.width = pct + '%';
                            uploadPct.textContent = pct + '%';
                        }
                    });

                    xhr.addEventListener('load', () => {
                        if (xhr.status >= 200 && xhr.status < 300) {
                            const res = JSON.parse(xhr.responseText);
                            targetValue.value = res.filename || file.name;
                            uploadedFilename.value = res.filename || file.name;
                            if (res.platform) platformSelect.value = res.platform;
                            dropLabel.innerHTML = '<span style="color:var(--accent);">✓ Upload complete</span>';
                            progressWrap.style.display = 'none';
                            if (res.project_id) uploadedFilename.dataset.projectId = res.project_id;
                            resolve(res);
                        } else {
                            try {
                                const err = JSON.parse(xhr.responseText);
                                reject(new Error(err.detail || 'Upload failed'));
                            } catch { reject(new Error('Upload failed: ' + xhr.status)); }
                        }
                    });

                    xhr.addEventListener('error', () => reject(new Error('Network error during upload')));
                    xhr.send(formData);
                });
            } catch (err) {
                progressWrap.style.display = 'none';
                setDropZoneError(err.message);
                targetValue.value = '';
            }
        }

        dropZone.addEventListener('click', () => fileInput.click());
        dropZone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') fileInput.click(); });

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) handleFile(fileInput.files[0]);
        });

        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.stopPropagation();
            setDropZoneActive(true);
            dropLabel.innerHTML = '<span style="color:var(--accent);">Release to upload</span>';
        });
        dropZone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            e.stopPropagation();
            setDropZoneActive(false);
            if (!targetValue.value) {
                dropLabel.innerHTML = 'Drop file here or <span style="color:var(--accent);text-decoration:underline;">browse</span>';
            }
        });
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            e.stopPropagation();
            setDropZoneActive(false);
            const files = e.dataTransfer?.files;
            if (files && files.length > 0) handleFile(files[0]);
        });

        document.addEventListener('dragover', (e) => e.preventDefault());
        document.addEventListener('drop', (e) => e.preventDefault());

        const radios = document.querySelectorAll('#scan-profile-group input[type="radio"]');
        const customPanel = document.getElementById('custom-tools-panel');

        radios.forEach(radio => {
            radio.addEventListener('change', () => {
                document.querySelectorAll('.radio-option').forEach(el => el.classList.remove('selected'));
                radio.closest('.radio-option').classList.add('selected');
                customPanel.style.display = radio.value === 'custom' ? 'block' : 'none';
            });
        });

        nameInput?.addEventListener('input', () => {
            const val = nameInput.value.toLowerCase();
            if (val.endsWith('.apk')) platformSelect.value = 'android';
            else if (val.endsWith('.ipa')) platformSelect.value = 'ios';
            else if (['.exe', '.dmg', '.deb'].some(e => val.endsWith(e))) platformSelect.value = 'desktop';
        });
    })();

    function cancelScan() {
        if (!_scanId) return;
        fetch(`/api/scan/cancel/${_scanId}`, { method: 'POST' })
            .then(() => window.irves?.showToast('Scan cancelled'));
    }

    function onScanComplete(findingsCount) {
        const btn = document.getElementById('view-results-btn');
        btn.href = `/dashboard?project=${_projectId}`;
        btn.style.opacity = '1';
        btn.style.pointerEvents = 'auto';

        if (_isFullScan) {
            const handoff = document.getElementById('runtime-handoff-panel');
            const summary = document.getElementById('handoff-summary');
            const proceedBtn = document.getElementById('proceed-runtime-btn');
            const skipLink = document.getElementById('skip-runtime-link');

            if (summary && findingsCount !== undefined) {
                summary.textContent = `Phase 1 complete — ${findingsCount} finding${findingsCount !== 1 ? 's' : ''} found. Phase 2: Runtime Instrumentation is ready.`;
            }
            if (handoff) handoff.style.display = 'block';

            proceedBtn?.addEventListener('click', () => {
                const targetUrl = `/runtime?project=${_projectId}&from_scan=${_scanId}`;
                if (window.parent !== window) {
                    window.parent.postMessage({ type: 'navigate', href: targetUrl }, '*');
                } else {
                    window.location.href = targetUrl;
                }
            });
            skipLink.href = `/dashboard?project=${_projectId}`;
        }
    }

    function startSSE() {
        if (_evtSource) {
            _evtSource.close();
            _evtSource = null;
        }
        
        _evtSource = new EventSource(`/api/events/scan/${_scanId}/stream`);

        function setStage(id, cls, msg) {
            const el = document.getElementById('stage-' + id);
            if (!el) return;
            el.className = 'pipeline-step pipeline-step--' + cls;
            const det = el.querySelector('.pipeline-step__detail');
            if (det && msg) det.innerText = msg;
            const ico = el.querySelector('.pipeline-step__status-icon');
            if (ico) {
                if (cls === 'running') ico.innerHTML = `<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6.5" stroke="var(--accent)" stroke-width="1.25" stroke-dasharray="4 2"/></svg>`;
                else if (cls === 'completed') ico.innerHTML = `<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6.5" fill="var(--accent)" opacity="0.2"/><path d="M5 8l2 2 4-4" stroke="var(--accent)" stroke-width="1.5" stroke-linecap="round"/></svg>`;
                else if (cls === 'failed') ico.innerHTML = `<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6.5" stroke="var(--critical)" stroke-width="1.25"/><path d="M6 6l4 4M10 6l-4 4" stroke="var(--critical)" stroke-width="1.25"/></svg>`;
            }
        }

        function inferStage(msg) {
            const m = (msg || '').toLowerCase();
            if (m.includes('apktool') || m.includes('decompil')) return 'apk_analyzer';
            if (m.includes('manifest')) return 'manifest';
            if (m.includes('pattern') || m.includes('smali') || m.includes('string')) return 'pattern_scan';
            if (m.includes('androguard') || m.includes('bytecode') || m.includes('class')) return 'bytecode';
            if (m.includes('ai') || m.includes('triage') || m.includes('pre-analyz')) return 'ai';
            if (m.includes('complete') || m.includes('total') || m.includes('final')) return 'complete';
            return null;
        }

        function handleEvent(e) {
            if (!e.data) return;
            let pdata;
            try { pdata = JSON.parse(e.data); } catch { return; }

            const evtType = pdata.type;

            if (evtType === 'init') {
                if (pdata.status === 'completed') {
                    document.getElementById('scan-status-subtitle').innerText = _isFullScan
                        ? '✓ Phase 1 already complete — proceed to Runtime Instrumentation'
                        : '✓ Scan already completed';
                    document.getElementById('progress-pct').innerText = '100%';
                    document.getElementById('progress-fill').style.width = '100%';
                    setStage('manifest', 'completed', 'Complete');
                    setStage('pattern_scan', 'completed', 'Complete');
                    setStage('bytecode', 'completed', 'Complete');
                    setStage('ai', 'completed', 'Complete');
                    setStage('complete', 'completed', 'Done');
                    onScanComplete();
                    _evtSource.close();
                    return;
                }
                document.getElementById('scan-status-subtitle').innerText = 'Starting up...';
                document.getElementById('progress-pct').innerText = (pdata.progress || 0) + '%';
                document.getElementById('progress-fill').style.width = (pdata.progress || 0) + '%';
            } else if (evtType === 'status') {
                document.getElementById('scan-status-subtitle').innerText = pdata.message || 'Running…';
            } else if (evtType === 'tool_start') {
                setStage(pdata.tool, 'running', pdata.message || 'Running…');
                setStage('apk_analyzer', 'running', pdata.message || 'Running…');
            } else if (evtType === 'tool_complete') {
                setStage(pdata.tool, 'completed', `✓ ${pdata.findings_count || 0} items`);
                if (pdata.tool === 'apk_analyzer') {
                    setStage('ai', 'running', 'Connecting to Claude…');
                } else if (pdata.tool === 'ai') {
                    setStage('complete', 'running', 'Finalizing…');
                }
            } else if (evtType === 'tool_error') {
                setStage(pdata.tool, 'failed', '✗ ' + (pdata.message || 'Error'));
            } else if (evtType === 'progress_pct') {
                const pct = (pdata.progress || 0) + '%';
                document.getElementById('progress-pct').innerText = pct;
                document.getElementById('progress-fill').style.width = pct;
                document.getElementById('progress-fill').closest('[role="progressbar"]')?.setAttribute('aria-valuenow', pdata.progress || 0);
            } else if (evtType === 'progress') {
                document.getElementById('scan-status-subtitle').innerText = pdata.message || '';
                const stage = inferStage(pdata.message);
                if (stage) setStage(stage, 'running', pdata.message);
            } else if (evtType === 'complete') {
                document.getElementById('scan-status-subtitle').innerText = _isFullScan
                    ? '✓ Phase 1 complete — ' + (pdata.findings_count || 0) + ' findings. Proceed to Runtime when ready.'
                    : '✓ Scan complete — ' + (pdata.findings_count || 0) + ' findings';
                document.getElementById('progress-pct').innerText = '100%';
                document.getElementById('progress-fill').style.width = '100%';
                setStage('complete', 'completed', 'Done');
                document.getElementById('progress-eta').innerText = _isFullScan ? 'Phase 1 Done' : 'Complete';
                onScanComplete(pdata.findings_count || 0);
                _evtSource.close();
            } else if (evtType === 'finding') {
                const list = document.getElementById('live-findings-list');
                const placeholder = document.getElementById('findings-placeholder');
                if (placeholder) placeholder.remove();
                const countEl = document.getElementById('live-finding-count');
                if (countEl) countEl.innerText = parseInt(countEl.innerText || '0') + 1;
                const wrapper = document.createElement('a');
                wrapper.className = 'finding-row';
                wrapper.href = pdata.finding_id ? `/findings/${pdata.finding_id}` : '#';
                wrapper.innerHTML = `
                    <div class="finding-row__severity">
                        <span class="severity-dot severity-dot--${pdata.severity}" aria-hidden="true"></span>
                    </div>
                    <div class="finding-row__content">
                        <div class="finding-row__title">${pdata.title}</div>
                        <div class="finding-row__location">${pdata.location || pdata.category || pdata.tool}</div>
                    </div>
                    <div class="finding-row__arrow" aria-hidden="true">›</div>
                `;
                list.appendChild(wrapper);
            } else if (evtType === 'error') {
                document.getElementById('scan-status-subtitle').style.color = 'var(--critical)';
                document.getElementById('scan-status-subtitle').innerText = 'Error: ' + (pdata.message || 'unknown error');
            }
        }

        ['init', 'status', 'tool_start', 'tool_complete', 'tool_error', 'progress_pct', 'progress', 'complete', 'finding', 'error'].forEach(eventType => {
            _evtSource.addEventListener(eventType, handleEvent);
        });

        _evtSource.addEventListener('message', handleEvent);

        _evtSource.onerror = function () {
            console.warn('SSE connection lost');
        };
    }
</script>
{% endblock %}
"""

with open('/home/orgilbold/Documents/Irves/backend/templates/screens/new_scan.html', 'w') as f:
    f.write(new_scan_raw)
print("done")
