(function() {
    const TAG = '[IrvesAI-Agent]';
    const toggleBtn  = document.getElementById('toggle-runtime-ai-btn');
    const drawer     = document.getElementById('runtime-ai-drawer');
    const closeBtn   = document.getElementById('runtime-ai-close');
    const history    = document.getElementById('runtime-ai-history');
    const input      = document.getElementById('runtime-ai-input');
    const submitBtn  = document.getElementById('runtime-ai-submit');
    let streaming = false;

    // ── Finding context from "Investigate in Runtime" link ──────────────────
    function resolveFindingId() {
        // Priority: URL param > DOM data attribute > sessionStorage
        const urlParams = new URLSearchParams(window.location.search);
        let fid = urlParams.get('finding_id');
        if (!fid) {
            const ctx = document.getElementById('runtime-context-data');
            if (ctx) fid = ctx.dataset.findingId;
        }
        if (!fid) {
            fid = sessionStorage.getItem('irves_runtime_finding_id');
        }
        if (fid) {
            sessionStorage.setItem('irves_runtime_finding_id', fid);
        }
        return fid || null;
    }
    const runtimeFindingId = resolveFindingId();

    // ── Markdown to HTML converter ───────────────────────────────────────────
    function mdToHtml(text) {
        if (!text) return '';
        let html = text
            // Escape HTML entities first
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            // Headers — cyan color, clean minimal style
            .replace(/^### (.*$)/gim, '<h4 style="margin:10px 0 6px 0;font-size:12px;font-weight:700;color:#22d3ee;text-transform:uppercase;letter-spacing:0.06em;">$1</h4>')
            .replace(/^## (.*$)/gim, '<h3 style="margin:14px 0 8px 0;font-size:13px;font-weight:700;color:#22d3ee;border-left:2px solid #22d3ee;padding-left:8px;">$1</h3>')
            .replace(/^# (.*$)/gim, '<h2 style="margin:16px 0 10px 0;font-size:14px;font-weight:700;color:#22d3ee;">$1</h2>')
            // Bold and Italic
            .replace(/\*\*\*(.*?)\*\*\*/g, '<strong><em>$1</em></strong>')
            .replace(/\*\*(.*?)\*\*/g, '<strong style="color:#f8fafc;">$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/___(.*?)___/g, '<strong><em>$1</em></strong>')
            .replace(/__(.*?)__/g, '<strong style="color:#f8fafc;">$1</strong>')
            .replace(/_(.*?)_/g, '<em>$1</em>')
            // Inline code
            .replace(/`([^`]+)`/g, '<code style="background:var(--surface-raised);padding:2px 6px;border-radius:4px;font-family:var(--font-mono);font-size:11px;color:#22d3ee;">$1</code>')
            // Code blocks — dark terminal style
            .replace(/```(\w+)?\n?([\s\S]*?)```/g, '<pre style="background:#0d1117;padding:12px;border-radius:6px;overflow-x:auto;margin:10px 0;border:1px solid rgba(34,211,238,0.2);"><code style="font-family:var(--font-mono);font-size:11px;line-height:1.6;color:#e6edf3;">$2</code></pre>')
            // Blockquote
            .replace(/^> (.*$)/gim, '<blockquote style="border-left:3px solid #22d3ee;margin:8px 0;padding-left:12px;color:var(--text-muted);font-style:italic;">$1</blockquote>')
            // Unordered lists
            .replace(/^\s*[-\*] (.*$)/gim, '<li style="margin:4px 0;margin-left:16px;color:#f8fafc;">$1</li>')
            // Ordered lists
            .replace(/^\s*\d+\.\s+(.*$)/gim, '<li style="margin:4px 0;margin-left:16px;list-style-type:decimal;color:#f8fafc;">$1</li>')
            // Links
            .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" style="color:#22d3ee;text-decoration:underline;">$1</a>')
            // Horizontal rule
            .replace(/^\s*---\s*$/gim, '<hr style="border:none;border-top:1px solid var(--border);margin:16px 0;">')
            // Line breaks
            .replace(/\n/g, '<br>');

        // Wrap consecutive list items in ul/ol
        html = html.replace(/(<li[^>]*>.*?<\/li>)(<br>)*\s*(<li[^>]*>.*?<\/li>)+/g, function(match) {
            const items = match.replace(/<br>/g, '');
            if (items.indexOf('list-style-type:decimal') !== -1) {
                return '<ol style="margin:8px 0;padding-left:0;">' + items + '</ol>';
            }
            return '<ul style="margin:8px 0;padding-left:0;list-style:none;">' + items + '</ul>';
        });

        return html;
    }

    if (!drawer) { console.warn(TAG, 'drawer element missing, aborting init'); return; }
    console.info(TAG, 'Agentic AI partner initialised');

    // ── Extract injectable code from pivot response ───────────────────────────
    // Handles both: ```json {"action":"inject_script","code":"..."} ``` (AI pivot format)
    // and plain JS fenced blocks produced by regular chat
    function extractPivotCode(text) {
        if (!text) return null;

        // Priority 1: JSON action block  ``` json\n{"action":"inject_script","code":"..."}\n```
        const jsonRe = /```(?:json)?\s*\n([\s\S]*?)```/g;
        let match, lastJson = null;
        while ((match = jsonRe.exec(text)) !== null) { lastJson = match[1]; }
        if (lastJson) {
            try {
                const parsed = JSON.parse(lastJson.trim());
                if (parsed && parsed.action === 'inject_script' && parsed.code) {
                    console.info(TAG, '[Pivot] extractPivotCode: JSON action block, code len:', parsed.code.length);
                    return parsed.code;
                }
            } catch(e) {}
        }

        // Priority 2: raw JS fenced block
        return extractLastCodeBlock(text);
    }

    // ── AI Pivot Bridge (receives auto-pivot events from runtime_workspace.js) ──
    let pivotBubble = null;
    let pivotBuffer = '';
    let pivotRenderTimer = null;

    function pivotRenderBuffer() {
        if (pivotBubble) {
            pivotBubble.innerHTML = mdToHtml(pivotBuffer);
            history.scrollTop = history.scrollHeight;
        }
        pivotRenderTimer = null;
    }

    window._irvesPivotBridge = {
        start: function(payload) {
            // Auto-open the drawer
            drawer.style.display = 'flex';

            // Label bubble
            const wrap = document.createElement('div');
            wrap.style.cssText = 'display:flex;flex-direction:column;gap:2px;';
            const label = document.createElement('div');
            label.style.cssText = 'font-size:10px;font-weight:700;letter-spacing:0.05em;text-transform:uppercase;color:var(--warn,#f59e0b);display:flex;align-items:center;gap:5px;';
            label.innerHTML = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg> Irves AI \u2014 Auto Pivot \u26a1';

            const bubble = document.createElement('div');
            bubble.className = 'ai-msg-content ai-msg-content--pivot';
            bubble.style.cssText = 'font-size:12px;line-height:1.6;color:var(--text-primary);background:rgba(245,158,11,0.06);border:1px solid rgba(245,158,11,0.3);border-radius:6px;padding:8px 10px;';
            bubble.innerHTML = '<em style="color:var(--warn,#f59e0b);">Analyzing error and pivoting strategy\u2026</em>';

            wrap.appendChild(label);
            wrap.appendChild(bubble);
            history.appendChild(wrap);
            history.scrollTop = history.scrollHeight;

            pivotBubble = bubble;
            pivotBuffer = '';
            console.info(TAG, '[Pivot] start');
        },
        token: function(chunk) {
            if (!pivotBubble) return;
            pivotBuffer += chunk;
            if (!pivotRenderTimer) {
                pivotRenderTimer = setTimeout(pivotRenderBuffer, 50);
            }
        },
        done: function(fullText) {
            if (pivotRenderTimer) { clearTimeout(pivotRenderTimer); }
            // Use fullText if buffer is empty (single-shot done without token events)
            if (!pivotBuffer && fullText) pivotBuffer = fullText;
            pivotRenderBuffer();

            // Offer inject button — try JSON action block first, then raw JS block
            if (pivotBubble) {
                const code = extractPivotCode(pivotBuffer);
                if (code) {
                    const injectWrap = document.createElement('div');
                    injectWrap.style.cssText = 'margin-top:8px;';
                    const injectBtn = document.createElement('button');
                    injectBtn.className = 'btn btn--primary btn--sm';
                    injectBtn.style.cssText = 'font-size:11px;padding:3px 10px;';
                    injectBtn.textContent = '\u26a1 Inject Suggested Fix';
                    injectBtn.onclick = function() {
                        if (executeScript(code)) {
                            injectBtn.textContent = '\u2713 Injected';
                            injectBtn.disabled = true;
                            injectBtn.style.opacity = '0.6';
                        }
                    };
                    injectWrap.appendChild(injectBtn);
                    pivotBubble.parentElement.appendChild(injectWrap);
                }
            }
            pivotBubble = null;
            pivotBuffer = '';
            console.info(TAG, '[Pivot] done');
        },
        error: function(msg) {
            if (pivotRenderTimer) { clearTimeout(pivotRenderTimer); }
            if (pivotBubble) {
                pivotBubble.innerHTML = '<span style="color:var(--critical);">\u2717 Pivot error: ' + (msg || 'unknown') + '</span>';
            }
            pivotBubble = null;
            pivotBuffer = '';
            console.error(TAG, '[Pivot] error:', msg);
        }
    };

    toggleBtn?.addEventListener('click', function() {
        const isHidden = drawer.style.display === 'none' || !drawer.style.display;
        drawer.style.display = isHidden ? 'flex' : 'none';
    });
    closeBtn?.addEventListener('click', function() { drawer.style.display = 'none'; });

    function getOutputLogs() {
        const stream = document.getElementById('output-stream');
        if (!stream) return '';
        const lines = stream.querySelectorAll('.output-line__msg');
        return Array.from(lines).map(function(l) { return l.textContent?.trim(); }).filter(Boolean).slice(-30).join('\n');
    }

    function getScriptContext() {
        const editor = document.getElementById('frida-script-editor');
        return editor ? editor.value : '';
    }

    function getRuntimeState() {
        const st = window._irvesRuntimeState || {};
        return {
            engine: st.engine || 'unknown',
            device_connected: !!st.fridaReady || !!st.xposedReady,
            websocket_connected: !!st.websocketConnected,
            session_active: !!st.sessionActive,
            device: st.device || st.serial || null,
            package: st.package || null,
            active_hooks: st.activeHooks || [],
            device_label: st.deviceLabel || 'unknown',
        };
    }

    function appendBubble(role, text) {
        const wrap = document.createElement('div');
        wrap.style.cssText = 'display:flex;flex-direction:column;gap:2px;';
        const label = document.createElement('div');
        label.style.cssText = 'font-size:10px;font-weight:700;letter-spacing:0.05em;text-transform:uppercase;color:' + (role === 'user' ? 'var(--accent)' : 'var(--text-muted)') + ';';
        label.textContent = role === 'user' ? 'You' : 'Irves AI';
        const bubble = document.createElement('div');
        bubble.className = 'ai-msg-content';
        bubble.style.cssText = 'font-size:12px;line-height:1.6;color:var(--text-primary);background:' + (role === 'user' ? 'rgba(99,102,241,0.08)' : 'var(--surface)') + ';border:1px solid var(--border);border-radius:6px;padding:8px 10px;';
        bubble.innerHTML = text ? mdToHtml(text) : '';
        wrap.appendChild(label);
        wrap.appendChild(bubble);
        history.appendChild(wrap);
        history.scrollTop = history.scrollHeight;
        return bubble;
    }

    // ── Execution intent detection ────────────────────────────────────────
    // Phrase keywords (multi-word)
    const EXEC_PHRASES = [
        'do it', 'run it', 'hook now', 'bypass now', 'bypass ssl',
        'bypass root', 'bypass pinning', 'dump dex', 'hook it',
        'go ahead', 'just do it', 'generate and inject', 'run this',
        'try it', 'fire it', 'send it', 'launch it', 'start it'
    ];
    // Single-word triggers — ONLY explicit action verbs that clearly mean "run it"
    // Topic nouns like 'frida', 'hook', 'bypass' are REMOVED — they appear in analysis questions
    const EXEC_WORDS = [
        'inject', 'execute', 'dump', 'apply', 'smash', 'exploit', 'patch'
    ];

    function detectExecIntent(msg) {
        const q = (msg || '').toLowerCase();
        // Phrases are highest-confidence triggers
        if (EXEC_PHRASES.some(function(p) { return q.indexOf(p) !== -1; })) return true;
        // Single words only trigger if they're NOT preceded by analysis words
        const blockedPrefixes = ['why ', 'how ', 'what ', 'is ', 'are ', 'can you explain', 'tell me about', 'analyze', 'look at', 'check', 'debug', 'fix', 'understand', 'meaning of', 'meaning', 'error', 'fail', 'not work', 'broken'];
        if (blockedPrefixes.some(function(p) { return q.indexOf(p) !== -1; })) return false;
        // Check individual words
        const words = q.replace(/[^a-z0-9\s]/g, ' ').split(/\s+/);
        return EXEC_WORDS.some(function(w) { return words.indexOf(w) !== -1; });
    }

    // ── Extract last code block from raw text (PERMISSIVE) ────────────────
    function extractLastCodeBlock(text) {
        // Very permissive: match ``` followed by optional anything on the same
        // line (language tag, spaces, etc.), then captured content, then ```
        const re = /```[^\n]*\n([\s\S]*?)```/g;
        let match, last = null;
        while ((match = re.exec(text)) !== null) { last = match; }
        if (!last) {
            console.warn(TAG, 'No fenced code block found (```...```)');
            console.warn(TAG, 'Full AI text length:', text.length, '| First 300 chars:', text.substring(0, 300));
            return null;
        }
        const code = last[1].trim();
        console.info(TAG, 'Extracted code block, length:', code.length, '| Preview:', code.substring(0, 120));

        // Very broad validation: accept anything that looks like it could
        // be a Frida/JS/native script (not just markdown or JSON)
        const FRIDA_SIGS = [
            'Java.perform', 'Java.use', 'Java.choose', 'Java.cast',
            'Interceptor.attach', 'Interceptor.replace',
            'Module.find', 'Module.load', 'Module.enumerate',
            'NativeFunction', 'NativeCallback', 'NativePointer',
            'send(', 'recv(', 'rpc.exports',
            'ObjC.classes', 'ObjC.choose',
            'Process.enumerate', 'Memory.read', 'Memory.write',
            'ptr(', 'new NativePointer',
            'console.log', 'function()', 'function ()',
        ];
        const hasSig = FRIDA_SIGS.some(function(s) { return code.indexOf(s) !== -1; });
        if (hasSig) return code;

        // Fallback: if code is > 50 chars and looks like JS (has braces/semicolons)
        if (code.length > 50 && (code.indexOf('{') !== -1 || code.indexOf(';') !== -1)) {
            console.info(TAG, 'Code block accepted via JS-heuristic fallback');
            return code;
        }

        console.warn(TAG, 'Code block rejected — no Frida signature and not JS-like. Code:', code.substring(0, 200));
        return null;
    }

    // ── Execute a Frida script via the editor + Run button ────────────────
    function executeScript(code) {
        const editor = document.getElementById('frida-script-editor');
        const runBtn = document.getElementById('run-script-btn');
        console.info(TAG, 'executeScript: editor found:', !!editor, '| runBtn found:', !!runBtn);

        if (!editor || !runBtn) return false;

        editor.value = code;
        // Dispatch input event so any listeners pick up the change
        editor.dispatchEvent(new Event('input', { bubbles: true }));
        console.info(TAG, 'Editor populated (' + code.length + ' chars). Clicking Run...');
        runBtn.click();
        return true;
    }

    // ── Main streaming chat function ──────────────────────────────────────
    // forceExecute: when true, always extract and run code from AI response
    async function streamRuntimeChat(question, forceExecute) {
        if (streaming) return;
        streaming = true;
        if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = '…'; }

        const shouldExecute = forceExecute || detectExecIntent(question);
        console.info(TAG, 'streamRuntimeChat | forceExec:', forceExecute, '| intentDetected:', detectExecIntent(question), '| shouldExecute:', shouldExecute, '| Q:', question);

        appendBubble('user', question);
        const bubble = appendBubble('ai', '');
        let tokenBuffer = '';
        let renderTimeout = null;

        // Debounced render function
        function renderBuffer() {
            bubble.innerHTML = mdToHtml(tokenBuffer);
            history.scrollTop = history.scrollHeight;
            renderTimeout = null;
        }

        const body = {
            message: question,
            script_context: getScriptContext(),
            logs: getOutputLogs(),
            runtime_state: getRuntimeState()
        };
        if (runtimeFindingId) {
            body.finding_id = runtimeFindingId;
        }

        try {
            const resp = await fetch('/api/analysis/runtime-chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            if (!resp.ok) throw new Error('Server ' + resp.status);

            const reader = resp.body.getReader();
            const decoder = new TextDecoder();
            let buf = '';

            while (true) {
                const chunk = await reader.read();
                if (chunk.done) {
                    if (renderTimeout) clearTimeout(renderTimeout);
                    renderBuffer();
                    break;
                }
                buf += decoder.decode(chunk.value, { stream: true });
                const sseLines = buf.split('\n');
                buf = sseLines.pop() || '';
                for (let i = 0; i < sseLines.length; i++) {
                    if (sseLines[i].indexOf('data: ') === 0) {
                        try {
                            const d = JSON.parse(sseLines[i].substring(6));
                            if (d.token) {
                                tokenBuffer += d.token;
                                // Debounce rendering for smooth performance
                                if (!renderTimeout) {
                                    renderTimeout = setTimeout(renderBuffer, 50);
                                }
                            }
                            if (d.error) {
                                tokenBuffer += '\n\n[Error: ' + d.error + ']';
                                if (renderTimeout) clearTimeout(renderTimeout);
                                renderBuffer();
                            }
                        } catch(e) {}
                    }
                }
            }

            const fullText = tokenBuffer;
            console.info(TAG, 'Stream complete. Text length:', fullText.length, '| shouldExecute:', shouldExecute);

            // ── AGENTIC EXECUTION (primary mechanism) ─────────────────────
            if (shouldExecute) {
                const code = extractLastCodeBlock(fullText);
                if (code) {
                    appendBubble('ai', '⚡ Executing — injecting script into target...');
                    if (executeScript(code)) {
                        console.info(TAG, 'Script injected successfully via editor + Run button');
                    } else {
                        appendBubble('ai', '⚠ Could not access script editor or Run button. Is the workspace loaded?');
                        console.error(TAG, 'executeScript returned false');
                    }
                } else {
                    appendBubble('ai', '⚠ No injectable Frida script found in AI response. The AI may not have included a code block. Try: "Write a Frida script to bypass SSL pinning"');
                    console.warn(TAG, 'extractLastCodeBlock returned null');
                }
            }

        } catch(e) {
            console.error(TAG, 'Stream error:', e);
            bubble.textContent += '\n\n[Connection Error: ' + e.message + ']';
        } finally {
            streaming = false;
            if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = 'Ask'; }
            if (input) input.focus();
        }
    }

    // ── Input handlers ────────────────────────────────────────────────────
    submitBtn?.addEventListener('click', function() {
        if (!input.value.trim()) return;
        const msg = input.value;
        input.value = '';
        streamRuntimeChat(msg, false);
    });
    input?.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') { e.preventDefault(); submitBtn.click(); }
    });

    // ── Quick action buttons — ALWAYS force execution ─────────────────────
    document.getElementById('ai-action-analyze-logs')?.addEventListener('click', function() {
        streamRuntimeChat('Analyze the recent runtime logs. What is the app doing and what attack surface do you see?', false);
    });
    document.getElementById('ai-action-suggest-hook')?.addEventListener('click', function() {
        streamRuntimeChat('Based on the current script and logs, write and inject a Frida hook to go deeper. Output only the script in a code block.', true);
    });
    document.getElementById('ai-action-bypass-root')?.addEventListener('click', function() {
        streamRuntimeChat('Write a complete Frida script to bypass root detection and emulator checks for this app. Output ONLY the code in a single fenced code block, no explanation.', true);
    });
    document.getElementById('ai-action-ssl-bypass')?.addEventListener('click', function() {
        streamRuntimeChat('Write a complete Frida script to bypass SSL certificate pinning (TrustManager, OkHttp, NetworkSecurityConfig). Output ONLY the code in a single fenced code block, no explanation.', true);
    });
    document.getElementById('ai-action-dump-dex')?.addEventListener('click', function() {
        streamRuntimeChat('Write a complete Frida script to dump unpacked DEX files from memory. Output ONLY the code in a single fenced code block, no explanation.', true);
    });

})();
