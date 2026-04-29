    // Make variables global to handle the unified screen state
    let _scanId = null;
    let _projectId = null;
    let _isFullScan = true;
    let _isRepoScan = false;
    let _evtSource = null;
    let _sourceType = 'upload'; // 'upload' | 'github' | 'gitlab'
    let _connectedProvider = null; // set when account is connected via OAuth
    let _authPollTimer = null; // OAuth authentication poll timer

    // ── Launchpad Source Selection ────────────────────────────────────────────
    function selectSource(type) {
        _sourceType = type;
        document.getElementById('source-type-value').value = type === 'upload' ? 'upload' : 'git';
        
        // Hide launchpad, show form
        document.getElementById('source-launchpad').style.display = 'none';
        const configStep = document.getElementById('config-step');
        configStep.style.display = 'block';

        // Scroll to form slightly
        configStep.scrollIntoView({ behavior: 'smooth', block: 'start' });

        const panelUpload = document.getElementById('panel-upload');
        const panelGit    = document.getElementById('panel-git');

        if (type === 'upload') {
            panelUpload.style.display = 'block';
            panelGit.style.display = 'none';
            _activateLocalProfiles();
        } else {
            panelUpload.style.display = 'none';
            panelGit.style.display = 'block';
            _activateRepoProfiles();
            checkAndConfigureGitPanel(type);
        }
    }

    function _activateLocalProfiles() {
        document.getElementById('scan-profile-group').style.display = 'flex';
        const rg = document.getElementById('repo-profile-group');
        rg.style.display = 'none';
        document.getElementById('custom-categories-panel').style.display = 'none';
        document.getElementById('pipeline-list').style.display = 'block';
        document.getElementById('repo-pipeline-list').style.display = 'none';
        // Restore platform to android default for binary scans
        const ps = document.getElementById('platform-select');
        if (ps && ps.value === 'repository') ps.value = 'android';
    }

    function _activateRepoProfiles() {
        document.getElementById('scan-profile-group').style.display = 'none';
        const rg = document.getElementById('repo-profile-group');
        rg.style.display = 'flex';
        document.getElementById('custom-tools-panel').style.display = 'none';
        document.getElementById('pipeline-list').style.display = 'none';
        document.getElementById('repo-pipeline-list').style.display = 'block';
        // Auto-select repository platform so backend validation passes
        const ps = document.getElementById('platform-select');
        if (ps) ps.value = 'repository';

        // Wire up repo profile radio change handler (idempotent)
        if (!rg._wired) {
            rg._wired = true;
            rg.querySelectorAll('input[type="radio"]').forEach(radio => {
                radio.addEventListener('change', () => {
                    rg.querySelectorAll('.radio-option').forEach(el => el.classList.remove('selected'));
                    radio.closest('.radio-option').classList.add('selected');
                    document.getElementById('custom-categories-panel').style.display =
                        radio.value === 'custom_repo' ? 'block' : 'none';
                });
            });
        }
    }

    function resetLaunchpad() {
        document.getElementById('source-launchpad').style.display = 'grid';
        document.getElementById('config-step').style.display = 'none';
    }

    async function checkAndConfigureGitPanel(provider) {
        // provider is 'github' or 'gitlab'
        const prompt = document.getElementById('git-connection-prompt');
        const ready = document.getElementById('git-account-ready');
        const manual = document.getElementById('manual-git-inputs');
        const list = document.getElementById('repo-selection-list');
        
        // Hide all initially
        prompt.style.display = 'none';
        ready.style.display = 'none';
        manual.style.display = 'none';
        list.style.display = 'none';
        
        // Update Connect button text and target
        const connectBtn = document.getElementById('btn-connect-git');
        connectBtn.innerHTML = `Connect ${provider.charAt(0).toUpperCase() + provider.slice(1)} Account`;
        connectBtn.onclick = () => {
            const authWin = window.open(`/api/auth/${provider}/login?return_to=/auth_success`, '_blank', 'width=600,height=800,scrollbars=yes');
            
            // Clear any existing poll timer
            if (_authPollTimer) {
                clearInterval(_authPollTimer);
                _authPollTimer = null;
            }
            
            // Poll to see if authentication succeeded
            _authPollTimer = setInterval(async () => {
                if (authWin && authWin.closed) {
                    clearInterval(_authPollTimer);
                    _authPollTimer = null;
                    checkAndConfigureGitPanel(provider);
                } else if (authWin) {
                    try {
                        const r = await fetch('/api/settings/settings');
                        const d = await r.json();
                        if (d.integrations && d.integrations[provider] && d.integrations[provider].connected) {
                            clearInterval(_authPollTimer);
                            _authPollTimer = null;
                            authWin.close();
                            checkAndConfigureGitPanel(provider);
                            window.irves?.showToast(`Connected as ${d.integrations[provider].username}!`);
                        }
                    } catch (e) {}
                }
            }, 1000);
        };

        try {
            const res = await fetch('/api/settings/settings');
            const data = await res.json();
            const integ = (data.integrations || {})[provider];

            if (integ && integ.connected) {
                // Show ready state
                ready.style.display = 'block';
                document.getElementById('connected-user-name').textContent = `Connected as ${integ.username}`;
                const avatar = document.getElementById('connected-user-avatar');
                if (integ.avatar) {
                    avatar.src = integ.avatar;
                    avatar.style.display = 'inline-block';
                } else {
                    avatar.style.display = 'none';
                }
                
                // Track connected provider — this marker is resolved to real token by backend
                _connectedProvider = provider;
            } else {
                // Show prompt to connect
                prompt.style.display = 'block';
            }
        } catch (e) {
            console.error("Failed to check Git integration", e);
            manual.style.display = 'block'; // fallback
        }
    }



    function showManualUrl() {
        document.getElementById('git-connection-prompt').style.display = 'none';
        document.getElementById('git-account-ready').style.display = 'none';
        document.getElementById('repo-selection-list').style.display = 'none';
        document.getElementById('manual-git-inputs').style.display = 'block';
        document.getElementById('repo-token-input').value = ''; // clear marker
    }

    async function showRepoSelector() {
        const list = document.getElementById('repo-selection-list');
        list.style.display = 'block';
        list.innerHTML = `<div style="padding:var(--sp-4); text-align:center; color:var(--text-muted); font-size:12px;">Loading repositories…</div>`;
        
        const provider = _sourceType; // 'github' or 'gitlab'
        try {
            const res = await fetch(`/api/auth/${provider}/repos`);
            if (!res.ok) throw new Error('Failed to fetch repositories');
            const repos = await res.json();
            
            if (repos.length === 0) {
                list.innerHTML = `<div style="padding:var(--sp-4); text-align:center; color:var(--text-muted); font-size:12px;">No repositories found.</div>`;
                return;
            }
            
            list.innerHTML = repos.map(r => `
                <div class="repo-item" onclick="selectGitRepo('${r.url}', '${r.default_branch || ''}')" style="padding:10px var(--sp-4); border-bottom:1px solid var(--border); cursor:pointer; transition:background .15s;" onmouseover="this.style.background='var(--surface-overlay)'" onmouseout="this.style.background='none'">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <div style="font-size:13px; font-weight:600; font-family:var(--font-mono);">${r.name}${r.private ? ' <span style="font-size:10px; opacity:0.6;">🔒</span>' : ''}</div>
                        <div style="font-size:10px; color:var(--text-muted); background:var(--surface-overlay); padding:1px 4px; border-radius:3px;">${r.default_branch || 'main'}</div>
                    </div>
                    ${r.description ? `<div style="font-size:11px; color:var(--text-muted); margin-top:2px;">${r.description}</div>` : ''}
                </div>
            `).join('');
            
        } catch (e) {
            list.innerHTML = `<div style="padding:var(--sp-4); text-align:center; color:var(--critical); font-size:12px;">Error: ${e.message}</div>`;
        }
    }

    function selectGitRepo(url, branch) {
        document.getElementById('repo-url-input').value = url;
        if (branch) {
            document.getElementById('repo-branch-input').value = branch;
            console.log("Selected default branch:", branch);
        }
        document.getElementById('repo-selection-list').style.display = 'none';
        window.irves?.showToast(`Selected repository (branch: ${branch || 'default'})`);
    }

    // ── Repository Verify ─────────────────────────────────────────────────────
    async function verifyRepo() {
        const btn    = document.getElementById('verify-repo-btn');

        const status = document.getElementById('repo-verify-status');
        const url    = document.getElementById('repo-url-input').value.trim();
        const token  = document.getElementById('repo-token-input').value.trim();

        if (!url) { status.textContent = '✗ Enter a repository URL first.'; status.style.color = 'var(--critical)'; return; }

        btn.disabled    = true;
        btn.textContent = 'Checking…';
        status.textContent = '';

        try {
            const res = await fetch('/api/scan/verify-repo', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ repo_url: url, repo_token: token || null }),
            });
            const data = await res.json();

            if (data.reachable) {
                status.style.color = 'var(--accent)';
                status.textContent = `✓ Reachable — default branch: ${data.default_branch}`;
                // Pre-fill branch input
                const branchInput = document.getElementById('repo-branch-input');
                if (data.default_branch && !branchInput.value.trim()) {
                    branchInput.value = data.default_branch;
                }
            } else {
                status.style.color = 'var(--critical)';
                status.textContent = `✗ ${data.error || 'Repository not reachable'}`;
            }
        } catch (e) {
            status.style.color = 'var(--critical)';
            status.textContent = '✗ Network error: ' + e.message;
        } finally {
            btn.disabled    = false;
            btn.textContent = 'Verify';
        }
    }


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
        const sourceType = _sourceType || 'upload';

        // ── Validation ────────────────────────────────────────────────────────
        if (sourceType === 'upload') {
            const targetValue = document.getElementById('target-value').value.trim();
            if (profile !== 'runtime' && !targetValue) {
                errBox.textContent = '✗ Please upload or select a target file first.';
                btn.disabled = false;
                btn.innerHTML = 'Begin Scan <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" /></svg>';
                return;
            }
        } else {
            const repoUrl = document.getElementById('repo-url-input').value.trim();
            if (!repoUrl) {
                errBox.textContent = '✗ Please enter a repository URL.';
                btn.disabled = false;
                btn.innerHTML = 'Begin Scan <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" /></svg>';
                return;
            }
        }

        try {
            let projectId = null;

            if (sourceType === 'github' || sourceType === 'gitlab' || sourceType === 'git') {
                // ── GIT REPO FLOW ─────────────────────────────────────────────
                const repoUrl   = document.getElementById('repo-url-input').value.trim();
                const repoBranch = document.getElementById('repo-branch-input').value.trim() || 'main';
                const manualToken = document.getElementById('repo-token-input').value.trim();
                const repoToken = _connectedProvider ? `__CONNECTED__:${_connectedProvider}` : (manualToken || null);

                // Determine repo profile
                const repoProfile = document.querySelector('[name="repo_profile"]:checked')?.value || 'full_source';
                const customCategories = repoProfile === 'custom_repo'
                    ? Array.from(document.querySelectorAll('input[name="categories"]:checked')).map(el => el.value)
                    : [];

                const projRes = await fetch('/api/scan/projects', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        name: projectName || repoUrl.split('/').pop() || 'Git Project',
                        platform: platform,
                        description: `Git scan — ${repoUrl}`,
                        source_type: 'git',
                        repo_url: repoUrl,
                        repo_branch: repoBranch,
                        repo_token: repoToken,
                    }),
                });
                if (!projRes.ok) {
                    const errBody = await projRes.json().catch(() => ({}));
                    const d = errBody.detail;
                    const msg = typeof d === 'string' ? d
                        : Array.isArray(d) ? d.map(e => e.msg || JSON.stringify(e)).join('; ')
                        : d ? JSON.stringify(d) : 'Failed to create project';
                    throw new Error(msg);
                }
                const project = await projRes.json();
                projectId = project.id;

                // Kick off source scan with repo profile
                const scanRes = await fetch('/api/scan/git-repo', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        project_id: projectId,
                        profile: repoProfile,
                        custom_categories: customCategories,
                    }),
                });
                if (!scanRes.ok) {
                    let errDetail = `HTTP ${scanRes.status}`;
                    try {
                        const errBody = await scanRes.json();
                        if (typeof errBody.detail === 'string') errDetail = errBody.detail;
                        else if (Array.isArray(errBody.detail)) errDetail = errBody.detail.map(e => e.msg || JSON.stringify(e)).join('; ');
                        else errDetail = JSON.stringify(errBody);
                    } catch (_) {}
                    throw new Error(errDetail);
                }
                const scan = await scanRes.json();

                // Show live panel with repo pipeline
                _scanId = scan.id;
                _projectId = projectId;
                _isFullScan = false;
                _isRepoScan = true;
                document.getElementById('live-scan-placeholder').style.display = 'none';
                document.getElementById('live-scan-panel').style.display = 'flex';
                document.getElementById('cancel-scan-btn').style.display = 'inline-flex';
                document.getElementById('live-scan-title').textContent = 'Source Code Analysis in Progress';
                startSSE();
                return; // done for git flow
            }

            // ── BINARY UPLOAD FLOW ────────────────────────────────────────────
            const targetValue = document.getElementById('target-value').value.trim();
            const uploadedFile = document.getElementById('uploaded-filename');
            const existingProjectId = uploadedFile?.dataset?.projectId || null;
            projectId = existingProjectId;

            if (!projectId) {
                const projRes = await fetch('/api/scan/projects', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        name: projectName || 'Unnamed Project',
                        platform: platform,
                        target_path: targetValue || null,
                        description: `${platform} scan — ${profile} profile`,
                        source_type: 'upload',
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
        // Repo scans redirect to Source Code Analysis screen
        btn.href = _isRepoScan
            ? `/source-analysis?project=${_projectId}`
            : `/dashboard?project=${_projectId}`;
        btn.textContent = _isRepoScan ? 'View Source Analysis' : 'View Full Results';
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
