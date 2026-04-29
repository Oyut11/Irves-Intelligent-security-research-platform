/* IRVES — Report Detail Screen JS */
// Get project ID from meta tag, URL param, or path
const getProjectId = () => {
    const metaId = document.querySelector('meta[name="project-id"]')?.content;
    if (metaId) return metaId;
    const urlParam = new URLSearchParams(window.location.search).get('project_id');
    if (urlParam) return urlParam;
    const pathParts = window.location.pathname.split('/').filter(p => p.length === 8);
    return pathParts[0] || '';
};
const projectId = getProjectId();

// Extract from URL: /source-analysis/report/{project_id}/{category}
const pathParts = window.location.pathname.split('/');
const reportIdx = pathParts.indexOf('report');
const catIdx = reportIdx >= 0 ? reportIdx + 2 : -1;
const projIdx = reportIdx >= 0 ? reportIdx + 1 : -1;
const category = catIdx >= 0 ? pathParts[catIdx] : '';
const projId = projIdx >= 0 ? pathParts[projIdx] : projectId;
const categoryLabel = category.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());

const catMeta = {
    architecture: { icon: '🏗️', color: '#6366f1' },
    scalability: { icon: '📈', color: '#8b5cf6' },
    code_quality: { icon: '✨', color: '#06b6d4' },
    security: { icon: '🛡️', color: '#ef4444' },
    dependencies: { icon: '📦', color: '#f59e0b' },
    secrets: { icon: '🔑', color: '#dc2626' },
    technical_debt: { icon: '🔧', color: '#84cc16' },
    contributor_risk: { icon: '👥', color: '#a855f7' },
};

let rawMarkdown = '';

document.addEventListener('DOMContentLoaded', loadReport);

async function loadReport() {
    const meta = catMeta[category] || { icon: '📋', color: '#6366f1' };
    const iconEl = document.getElementById('report-icon');
    if (iconEl) iconEl.textContent = meta.icon;
    document.title = categoryLabel + ' Report — IRVES';

    try {
        const res = await fetch(`/api/source-analysis/${projId}/category/${category}?limit=100`);
        if (!res.ok) {
            document.getElementById('report-content').innerHTML = '<div style="padding:48px;color:var(--text-muted);text-align:center;">No analysis available. Run analysis first.</div>';
            return;
        }
        const data = await res.json();
        const reportFinding = data.findings?.find(f => f.type && f.type.endsWith('_report'));
        if (reportFinding) {
            rawMarkdown = reportFinding.message || '';
            renderFullReport(data, reportFinding);
        } else {
            renderStandardFindings(data);
        }
    } catch (e) {
        document.getElementById('report-content').innerHTML = '<div style="padding:16px;color:var(--high);">Failed to load report.</div>';
    }
}

function renderFullReport(data, reportFinding) {
    const extra = reportFinding.metadata || reportFinding.extra_data || {};
    const score = extra.security_score || extra.secret_score || 0;
    const critCount = extra.critical_count || 0;
    const highCount = extra.high_count || 0;

    const badge = document.getElementById('report-status-badge');
    if (badge) { badge.textContent = data.status || '—'; badge.className = 'severity-badge severity-badge--' + (data.status === 'completed' ? 'low' : 'medium'); }
    const scoreEl = document.getElementById('report-score');
    if (scoreEl) scoreEl.textContent = score ? 'Score: ' + score + '/10' : '—';
    const durEl = document.getElementById('report-duration');
    if (durEl) durEl.textContent = data.duration_seconds ? data.duration_seconds.toFixed(1) + 's' : '—';

    // Parse counts from markdown
    const critM = rawMarkdown.match(/Critical Findings:\*\*\s*(\d+)/);
    const highM = rawMarkdown.match(/High Severity:\*\*\s*(\d+)/);
    const medM = rawMarkdown.match(/Medium Severity:\*\*\s*(\d+)/);
    setText('stat-crit', critM ? critM[1] : critCount);
    setText('stat-high', highM ? highM[1] : highCount);
    setText('stat-med', medM ? medM[1] : 0);
    setText('stat-low', 0);
    setText('stat-score', score || '—');

    const sections = parseSections(rawMarkdown);
    renderSections(sections);
    buildTOC(sections);
    initScrollSpy();
}

function parseSections(md) {
    const lines = md.split('\n');
    const sections = [];
    let current = null;
    for (const line of lines) {
        if (line.startsWith('# ') && !line.startsWith('## ')) continue;
        if (line.startsWith('## ')) {
            if (current) sections.push(current);
            current = { title: line.replace('## ', '').trim(), lines: [], level: 2 };
        } else if (current) {
            current.lines.push(line);
        }
    }
    if (current) sections.push(current);
    return sections;
}

function renderSections(sections) {
    const container = document.getElementById('report-content');
    let html = '';
    for (let i = 0; i < sections.length; i++) {
        const s = sections[i];
        const t = s.title.toLowerCase();
        const isVuln = t.includes('critical') || t.includes('high severity') || t.includes('medium severity');
        const isScore = t.includes('scorecard');
        const isCheck = t.includes('best practices') || t.includes('assessment');
        const isOWASP = t.includes('owasp') || t.includes('compliance');
        const isRec = t.includes('recommendation');

        html += '<section class="report-section" id="section-' + i + '">';
        html += '<h2 class="report-section__title">' + esc(s.title) + '</h2>';

        if (isVuln) html += renderVulnCards(s.lines);
        else if (isScore) html += renderScorecard(s.lines);
        else if (isCheck) html += renderChecklist(s.lines);
        else if (isOWASP) html += renderOWASP(s.lines);
        else if (isRec) html += renderRecs(s.lines);
        else html += renderGeneric(s.lines);

        html += '</section>';
    }
    container.innerHTML = html;
}

function renderVulnCards(lines) {
    let html = '', card = null;
    for (const line of lines) {
        const m = line.match(/^###\s+\d+\.\s+(.+)$/);
        if (m) {
            if (card) html += closeCard(card);
            const t = m[1];
            let sev = 'medium';
            if (t.includes('CRITICAL')) sev = 'critical';
            else if (t.includes('HIGH')) sev = 'high';
            card = { sev, title: t, body: [], rec: [], inRec: false };
            continue;
        }
        if (!card) continue;
        if (line.includes('**Recommendation:**') || (card.inRec && line.startsWith('- '))) {
            card.inRec = true;
            card.rec.push(line.replace(/\*\*Recommendation:\*\*\s*/, ''));
        } else {
            card.inRec = false;
            card.body.push(line);
        }
    }
    if (card) html += closeCard(card);
    return html;
}

function closeCard(c) {
    const body = c.body.map(l => renderL(l)).join('');
    const rec = c.rec.length ? '<div class="finding-card__recommendation"><strong>Recommendation:</strong> ' + c.rec.map(r => renderL(r)).join('') + '</div>' : '';
    return '<div class="finding-card finding-card--' + c.sev + '">' +
        '<div class="finding-card__header"><div class="finding-card__title">' + renderL(c.title) + '</div>' +
        '<span class="severity-badge severity-badge--' + c.sev + '" style="font-size:10px;">' + c.sev.toUpperCase() + '</span></div>' +
        '<div class="finding-card__body">' + body + '</div>' + rec + '</div>';
}

function renderScorecard(lines) {
    const rows = [];
    for (const l of lines) {
        const m = l.match(/^\|\s*(.+?)\s*\|\s*(\d[\d.]*)\/10\s*\|\s*(.+?)\s*\|$/);
        if (m) rows.push({ cat: m[1].replace(/\*\*/g, '').trim(), score: m[2], status: m[3].trim(), total: m[1].includes('**') });
    }
    if (!rows.length) return renderGeneric(lines);
    let h = '<table class="scorecard-table"><thead><tr><th>Category</th><th>Score</th><th>Status</th></tr></thead><tbody>';
    for (const r of rows) {
        const sc = parseFloat(r.score) >= 7 ? 'good' : parseFloat(r.score) >= 5 ? 'moderate' : 'critical';
        h += '<tr' + (r.total ? ' class="total-row"' : '') + '><td>' + esc(r.cat) + '</td><td><span class="score-value score-value--' + sc + '">' + r.score + '/10</span></td><td>' + r.status + '</td></tr>';
    }
    return h + '</tbody></table>';
}

function renderChecklist(lines) {
    const items = [];
    for (const l of lines) {
        const m = l.match(/^- ([✅❌⚠️])\s+(.+)/);
        if (m) {
            let cls = 'warn';
            if (m[1] === '✅') cls = 'pass';
            else if (m[1] === '❌') cls = 'fail';
            items.push({ cls, text: m[2] });
        }
    }
    if (!items.length) return renderGeneric(lines);
    return '<ul class="check-list">' + items.map(i => '<li class="' + i.cls + '">' + esc(i.text) + '</li>').join('') + '</ul>';
}

function renderOWASP(lines) {
    const rows = [];
    for (const l of lines) {
        const m = l.match(/^\|\s*(A\d{2}[^|]+?)\s*\|\s*([❌✅⚠️]+)\s*\|\s*([^|]*?)\s*\|$/);
        if (m) rows.push({ cat: m[1].trim(), status: m[2].trim(), notes: m[3].trim() });
    }
    if (!rows.length) return renderGeneric(lines);
    let h = '<table class="owasp-table"><thead><tr><th>Category</th><th>Status</th><th>Notes</th></tr></thead><tbody>';
    for (const r of rows) h += '<tr><td>' + esc(r.cat) + '</td><td>' + r.status + '</td><td style="color:var(--text-muted);">' + esc(r.notes) + '</td></tr>';
    return h + '</tbody></table>';
}

function renderRecs(lines) {
    let h = '';
    for (const l of lines) {
        if (l.startsWith('### ')) {
            const sub = l.replace('### ', '').trim();
            const icon = sub.includes('Immediate') ? '🔴' : sub.includes('High') ? '🟠' : sub.includes('Medium') ? '🟡' : '🟢';
            h += '<h3 style="font-size:13px;font-weight:600;color:var(--text-primary);margin:16px 0 8px;">' + icon + ' ' + esc(sub) + '</h3>';
        } else if (l.startsWith('- ')) {
            h += '<div style="font-size:12px;color:var(--text-primary);line-height:1.7;padding-left:16px;">' + renderL(l.substring(2)) + '</div>';
        } else if (l.trim()) {
            h += renderL(l);
        }
    }
    return h;
}

function renderGeneric(lines) {
    let h = '', inTable = false;
    for (const l of lines) {
        if (l.startsWith('### ')) {
            if (inTable) { h += '</tbody></table>'; inTable = false; }
            h += '<h3 style="font-size:14px;font-weight:600;color:var(--text-primary);margin:16px 0 8px;">' + esc(l.replace('### ', '')) + '</h3>';
        } else if (l.startsWith('|') && l.endsWith('|')) {
            if (!inTable) { h += '<table class="scorecard-table"><tbody>'; inTable = true; }
            const cells = l.split('|').slice(1, -1).map(c => c.trim());
            if (cells.every(c => /^[-:]+$/.test(c))) continue;
            h += '<tr>' + cells.map(c => '<td>' + renderL(c) + '</td>').join('') + '</tr>';
        } else {
            if (inTable) { h += '</tbody></table>'; inTable = false; }
            h += renderL(l);
        }
    }
    if (inTable) h += '</tbody></table>';
    return h;
}

function renderL(text) {
    if (!text) return '';
    let h = esc(text);
    h = h.replace(/`([^`]+)`/g, '<code style="background:rgba(255,255,255,0.06);padding:1px 4px;border-radius:3px;font-size:11px;">$1</code>');
    h = h.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    h = h.replace(/\*([^*]+)\*/g, '<em>$1</em>');
    return h;
}

function renderStandardFindings(data) {
    document.getElementById('report-content').innerHTML = '<div style="padding:48px;color:var(--text-muted);text-align:center;">Standard findings view.</div>';
}

function buildTOC(sections) {
    const nav = document.getElementById('toc-nav');
    if (!nav) return;
    nav.innerHTML = sections.map((s, i) =>
        '<a class="toc-link" href="#section-' + i + '" data-section="' + i + '">' + esc(s.title) + '</a>'
    ).join('');
}

function initScrollSpy() {
    const links = document.querySelectorAll('.toc-link');
    const observer = new IntersectionObserver(entries => {
        entries.forEach(e => {
            if (e.isIntersecting) {
                links.forEach(l => l.classList.remove('active'));
                const idx = e.target.id.replace('section-', '');
                const link = document.querySelector('.toc-link[data-section="' + idx + '"]');
                if (link) link.classList.add('active');
            }
        });
    }, { rootMargin: '-80px 0px -60% 0px' });
    document.querySelectorAll('.report-section').forEach(s => observer.observe(s));
}

function exportMarkdown() {
    if (!rawMarkdown) return;
    const blob = new Blob([rawMarkdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = categoryLabel.replace(/\s+/g, '_') + '_Report.md';
    a.click();
    URL.revokeObjectURL(url);
}

function setText(id, val) { const el = document.getElementById(id); if (el) el.textContent = val; }
function esc(s) { if (!s) return ''; return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
