// Traffic Cypher — Password Manager SPA
// Liquid Glass Dark Theme with Green Glow

(function() {
    'use strict';

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------
    let sessionToken = null;
    let credentials = [];
    let selectedId = null;
    let currentView = 'vault'; // vault | settings | help | visualizer
    let totpTimers = {};
    let statusInterval = null;
    let dangerModeTimer = null;
    let visualizerInterval = null;

    // -----------------------------------------------------------------------
    // API Layer
    // -----------------------------------------------------------------------
    const API = '/api';

    async function api(method, path, body) {
        const opts = {
            method,
            headers: { 'Content-Type': 'application/json' },
        };
        if (sessionToken) {
            opts.headers['Authorization'] = `Bearer ${sessionToken}`;
        }
        if (body) {
            opts.body = JSON.stringify(body);
        }
        const res = await fetch(`${API}${path}`, opts);
        const data = await res.json();
        if (res.status === 401 && path !== '/auth/unlock') {
            sessionToken = null;
            renderApp();
            throw new Error('Session expired');
        }
        if (!res.ok) {
            throw new Error(data.error || 'Request failed');
        }
        return data;
    }

    // -----------------------------------------------------------------------
    // Toast
    // -----------------------------------------------------------------------
    function showToast(msg, type = 'success') {
        const existing = document.querySelector('.toast');
        if (existing) existing.remove();
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = msg;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 2500);
    }

    // -----------------------------------------------------------------------
    // Clipboard
    // -----------------------------------------------------------------------
    async function copyToClipboard(text, label) {
        try {
            await navigator.clipboard.writeText(text);
            showToast(`${label || 'Text'} copied`);
            setTimeout(() => navigator.clipboard.writeText(''), 30000);
        } catch {
            showToast('Copy failed', 'error');
        }
    }

    // -----------------------------------------------------------------------
    // Render Engine
    // -----------------------------------------------------------------------
    function $(sel) { return document.querySelector(sel); }
    function $$(sel) { return document.querySelectorAll(sel); }

    function renderApp() {
        const app = $('#app');
        if (!sessionToken) {
            renderUnlock(app);
        } else {
            renderMain(app);
        }
    }

    // -----------------------------------------------------------------------
    // Unlock Screen
    // -----------------------------------------------------------------------
    function renderUnlock(app) {
        app.innerHTML = `
            <div class="unlock-screen">
                <div class="unlock-card glass">
                    <span class="logo-icon">\u{1F512}</span>
                    <h1>Traffic Cypher</h1>
                    <p class="subtitle">Entropy-driven password manager</p>
                    <form id="unlock-form">
                        <input type="password" id="master-pw" placeholder="Master password" autocomplete="current-password" autofocus>
                        <div style="height:16px"></div>
                        <button type="submit" class="btn btn-primary btn-full" id="unlock-btn">Unlock</button>
                        <p id="unlock-error" style="color:var(--danger);font-size:13px;margin-top:12px;display:none"></p>
                    </form>
                </div>
            </div>
        `;
        $('#unlock-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = $('#unlock-btn');
            const pw = $('#master-pw').value;
            if (!pw) return;
            btn.disabled = true;
            btn.textContent = 'Unlocking...';
            try {
                const data = await api('POST', '/auth/unlock', { master_password: pw });
                sessionToken = data.token;
                await loadCredentials();
                renderApp();
                startStatusPolling();
            } catch (err) {
                $('#unlock-error').style.display = 'block';
                $('#unlock-error').textContent = err.message;
                btn.disabled = false;
                btn.textContent = 'Unlock';
            }
        });
    }

    // -----------------------------------------------------------------------
    // Main Layout
    // -----------------------------------------------------------------------
    function renderMain(app) {
        app.innerHTML = `
            <div class="top-bar">
                <span style="font-weight:700;font-size:15px;color:var(--green-bright)">\u{1F6A6} Traffic Cypher</span>
                <div class="nav-tabs">
                    <button class="nav-tab ${currentView === 'vault' ? 'active' : ''}" data-view="vault">\u{1F513} Vault</button>
                    <button class="nav-tab ${currentView === 'visualizer' ? 'active' : ''}" data-view="visualizer">\u26A1 Visualizer</button>
                    <button class="nav-tab ${currentView === 'settings' ? 'active' : ''}" data-view="settings">\u2699\uFE0F Settings</button>
                    <button class="nav-tab ${currentView === 'help' ? 'active' : ''}" data-view="help">\u2753 Help</button>
                </div>
                <button class="btn btn-secondary btn-icon" id="lock-btn" title="Lock vault">\u{1F512}</button>
            </div>
            <div id="main-content"></div>
            <div class="status-bar" id="status-bar">
                <div class="status-indicator">
                    <span class="dot pulse" id="rotation-dot" style="background:var(--green-glow);box-shadow:0 0 8px var(--green-glow)"></span>
                    <span id="rotation-info">Key rotation active</span>
                </div>
                <div class="status-indicator">
                    <span id="stream-info">Streams: connecting...</span>
                </div>
                <div style="flex:1"></div>
                <span id="entry-count">${credentials.length} entries</span>
            </div>
        `;

        // Nav tabs
        $$('.nav-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                currentView = tab.dataset.view;
                renderApp();
            });
        });

        // Lock button
        $('#lock-btn').addEventListener('click', async () => {
            try {
                await api('POST', '/auth/lock');
            } catch {}
            sessionToken = null;
            credentials = [];
            selectedId = null;
            stopStatusPolling();
            renderApp();
        });

        // Render current view
        const content = $('#main-content');
        stopVisualizerPolling();
        if (currentView === 'vault') renderVault(content);
        else if (currentView === 'visualizer') renderVisualizer(content);
        else if (currentView === 'settings') renderSettings(content);
        else if (currentView === 'help') renderHelp(content);
    }

    // -----------------------------------------------------------------------
    // Vault View
    // -----------------------------------------------------------------------
    function renderVault(container) {
        container.innerHTML = `
            <div class="main-layout">
                <div class="sidebar">
                    <div class="sidebar-header">
                        <h2>\u{1F511} Passwords</h2>
                        <div class="sidebar-actions">
                            <button class="btn btn-primary btn-icon" id="add-btn" title="Add credential">+</button>
                        </div>
                    </div>
                    <div class="search-box">
                        <div class="search-wrapper">
                            <input type="text" id="search-input" placeholder="Search passwords...">
                        </div>
                    </div>
                    <div class="credential-list" id="credential-list"></div>
                </div>
                <div class="detail-pane" id="detail-pane"></div>
            </div>
        `;

        renderCredentialList();
        renderDetailPane();

        $('#add-btn').addEventListener('click', () => openAddEditModal());

        let searchTimeout;
        $('#search-input').addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                loadCredentials(e.target.value).then(() => renderCredentialList());
            }, 200);
        });
    }

    function renderCredentialList() {
        const list = $('#credential-list');
        if (!list) return;

        if (credentials.length === 0) {
            list.innerHTML = `
                <div style="text-align:center;padding:40px 20px;color:var(--text-muted)">
                    <div style="font-size:32px;margin-bottom:8px;opacity:0.3">\u{1F510}</div>
                    <p style="font-size:13px">No passwords yet</p>
                    <p style="font-size:12px;margin-top:4px">Click + to add your first</p>
                </div>
            `;
            return;
        }

        list.innerHTML = credentials.map(c => `
            <div class="credential-item ${c.id === selectedId ? 'active' : ''}" data-id="${c.id}">
                <div class="credential-avatar">${getInitial(c)}</div>
                <div class="credential-info">
                    <div class="name">${esc(c.label)}</div>
                    <div class="detail">${esc(c.username || c.website || '')}</div>
                </div>
                ${c.totp_secret ? '<span style="font-size:11px;color:var(--green-dim)">\u{1F551}</span>' : ''}
            </div>
        `).join('');

        $$('.credential-item').forEach(item => {
            item.addEventListener('click', () => {
                selectedId = item.dataset.id;
                renderCredentialList();
                renderDetailPane();
            });
        });
    }

    function renderDetailPane() {
        deactivateDangerMode();
        const pane = $('#detail-pane');
        if (!pane) return;

        if (!selectedId) {
            pane.innerHTML = `
                <div class="empty-state">
                    <div class="icon">\u{1F510}</div>
                    <p style="font-size:16px;font-weight:500">Select a credential</p>
                    <p style="font-size:13px;margin-top:4px">Choose from the sidebar or add a new one</p>
                </div>
            `;
            return;
        }

        const c = credentials.find(x => x.id === selectedId);
        if (!c) {
            pane.innerHTML = '<div class="empty-state"><p>Credential not found</p></div>';
            return;
        }

        let totpHtml = '';
        if (c.totp_secret) {
            totpHtml = `
                <div class="totp-section glass-sm">
                    <div class="field-label">TWO-FACTOR CODE</div>
                    <div class="totp-code" id="totp-code">------</div>
                    <div class="totp-timer" id="totp-timer">
                        <svg width="48" height="48" viewBox="0 0 48 48">
                            <circle cx="24" cy="24" r="20" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="3"/>
                            <circle cx="24" cy="24" r="20" fill="none" stroke="var(--green-glow)" stroke-width="3"
                                stroke-dasharray="125.6" stroke-dashoffset="0" stroke-linecap="round" id="totp-ring"/>
                        </svg>
                        <span class="countdown-text" id="totp-seconds">30</span>
                    </div>
                    <button class="copy-btn" style="margin-top:8px;cursor:pointer;background:none;border:none;color:var(--text-muted);font-size:13px" id="copy-totp">Copy code</button>
                </div>
            `;
        }

        let tagsHtml = '';
        if (c.tags && c.tags.length > 0) {
            tagsHtml = `
                <div class="field-group">
                    <div class="field-label">TAGS</div>
                    <div class="tags">${c.tags.map(t => `<span class="tag">${esc(t)}</span>`).join('')}</div>
                </div>
            `;
        }

        let notesHtml = '';
        if (c.notes) {
            notesHtml = `
                <div class="field-group">
                    <div class="field-label">NOTES</div>
                    <div class="notes-content">${esc(c.notes)}</div>
                </div>
            `;
        }

        let historyHtml = '';
        if (c.password_history && c.password_history.length > 0) {
            historyHtml = `
                <div class="field-group">
                    <button class="history-toggle" id="toggle-history">\u25B6 Password history (${c.password_history.length})</button>
                    <div class="history-list" id="history-list" style="display:none">
                        ${c.password_history.map(h => `
                            <div class="history-item">
                                <span class="pw">${esc(h.password)}</span>
                                <span class="date">${formatDate(h.changed_at)}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        pane.innerHTML = `
            <div class="detail-card glass">
                <div class="detail-header">
                    <div class="detail-avatar">${getInitial(c)}</div>
                    <div class="detail-title">
                        <h2>${esc(c.label)}</h2>
                        ${c.website ? `<div class="url">${esc(c.website)}</div>` : ''}
                    </div>
                    <div class="detail-actions">
                        <button class="btn btn-secondary btn-icon" id="edit-cred" title="Edit">\u270F\uFE0F</button>
                        <button class="btn btn-danger btn-icon" id="delete-cred" title="Delete">\u{1F5D1}\uFE0F</button>
                    </div>
                </div>

                ${c.username ? `
                <div class="field-group">
                    <div class="field-label">USERNAME</div>
                    <div class="field-value">
                        <span class="text">${esc(c.username)}</span>
                        <button class="copy-btn" data-copy="${esc(c.username)}" data-label="Username">Copy</button>
                    </div>
                </div>` : ''}

                <div class="field-group" id="pw-field-group">
                    <div class="field-label">PASSWORD</div>
                    <div class="field-value" id="pw-field-value">
                        <span class="text mono" id="pw-display"><span class="password-masked">\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022</span></span>
                        <div id="danger-countdown-wrap" style="display:none"></div>
                        <button class="copy-btn" id="toggle-pw" title="Reveal password">\u{1F441}\uFE0F</button>
                        <button class="copy-btn" id="copy-pw">Copy</button>
                    </div>
                </div>

                ${totpHtml}
                ${tagsHtml}
                ${notesHtml}
                ${historyHtml}

                <div style="font-size:12px;color:var(--text-muted);margin-top:20px;display:flex;gap:20px">
                    <span>Created: ${formatDate(c.created_at)}</span>
                    <span>Updated: ${formatDate(c.updated_at)}</span>
                </div>
            </div>
        `;

        // Password toggle — Danger Mode
        $('#toggle-pw').addEventListener('click', () => openDangerModeModal(c));
        $('#copy-pw').addEventListener('click', () => copyToClipboard(c.password, 'Password'));

        // Copy buttons
        pane.querySelectorAll('[data-copy]').forEach(btn => {
            btn.addEventListener('click', () => copyToClipboard(btn.dataset.copy, btn.dataset.label));
        });

        // Edit / Delete
        $('#edit-cred').addEventListener('click', () => openAddEditModal(c));
        $('#delete-cred').addEventListener('click', () => confirmDelete(c));

        // History toggle
        if ($('#toggle-history')) {
            $('#toggle-history').addEventListener('click', () => {
                const list = $('#history-list');
                const btn = $('#toggle-history');
                if (list.style.display === 'none') {
                    list.style.display = 'block';
                    btn.innerHTML = `\u25BC Password history (${c.password_history.length})`;
                } else {
                    list.style.display = 'none';
                    btn.innerHTML = `\u25B6 Password history (${c.password_history.length})`;
                }
            });
        }

        // TOTP
        if (c.totp_secret) {
            startTotpPolling(c.id);
            const copyTotpBtn = $('#copy-totp');
            if (copyTotpBtn) {
                copyTotpBtn.addEventListener('click', () => {
                    const code = $('#totp-code').textContent;
                    if (code && code !== '------') copyToClipboard(code, 'TOTP code');
                });
            }
        }
    }

    // -----------------------------------------------------------------------
    // TOTP Polling
    // -----------------------------------------------------------------------
    function startTotpPolling(credId) {
        stopTotpPolling();
        async function poll() {
            try {
                const data = await api('GET', `/credentials/${credId}/totp`);
                const codeEl = document.getElementById('totp-code');
                const ringEl = document.getElementById('totp-ring');
                const secEl = document.getElementById('totp-seconds');
                if (codeEl) {
                    codeEl.textContent = data.code.replace(/(.{3})/, '$1 ');
                }
                if (ringEl) {
                    const offset = (1 - data.seconds_remaining / 30) * 125.6;
                    ringEl.setAttribute('stroke-dashoffset', offset.toString());
                }
                if (secEl) {
                    secEl.textContent = data.seconds_remaining;
                }
            } catch {}
        }
        poll();
        totpTimers.interval = setInterval(poll, 1000);
    }

    function stopTotpPolling() {
        if (totpTimers.interval) {
            clearInterval(totpTimers.interval);
            totpTimers.interval = null;
        }
    }

    // -----------------------------------------------------------------------
    // Add/Edit Modal
    // -----------------------------------------------------------------------
    function openAddEditModal(existing) {
        const isEdit = !!existing;
        let genPassword = '';
        let genStrength = null;

        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.innerHTML = `
            <div class="modal glass">
                <h3>${isEdit ? 'Edit Credential' : 'Add Credential'}</h3>
                <form id="cred-form">
                    <div class="form-group">
                        <label>Label *</label>
                        <input type="text" id="f-label" value="${esc(existing?.label || '')}" placeholder="e.g. GitHub" required>
                    </div>
                    <div class="form-group">
                        <label>Website</label>
                        <input type="text" id="f-website" value="${esc(existing?.website || '')}" placeholder="https://github.com">
                    </div>
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" id="f-username" value="${esc(existing?.username || '')}" placeholder="user@email.com">
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="text" id="f-password" value="${esc(existing?.password || '')}" placeholder="Enter or generate" style="font-family:monospace">
                    </div>
                    <div class="password-generator glass-sm" id="pw-gen-section">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
                            <span style="font-size:13px;font-weight:600;color:var(--text-secondary)">Password Generator</span>
                            <button type="button" class="btn btn-secondary" id="gen-btn" style="padding:6px 14px;font-size:13px">Generate</button>
                        </div>
                        <div class="generator-preview" id="gen-preview">Click Generate</div>
                        <div class="strength-meter"><div class="fill" id="strength-fill" style="width:0"></div></div>
                        <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px" id="strength-label"></div>
                        <div class="range-row">
                            <span style="font-size:12px;color:var(--text-muted)">Length</span>
                            <input type="range" id="gen-length" min="8" max="64" value="24">
                            <span id="gen-length-val">24</span>
                        </div>
                        <div class="generator-options">
                            <label><input type="checkbox" id="gen-upper" checked> ABC</label>
                            <label><input type="checkbox" id="gen-lower" checked> abc</label>
                            <label><input type="checkbox" id="gen-digits" checked> 123</label>
                            <label><input type="checkbox" id="gen-symbols" checked> !@#</label>
                        </div>
                        <button type="button" class="btn btn-secondary btn-full" id="use-gen-pw" style="margin-top:10px;font-size:13px;padding:8px">Use generated password</button>
                    </div>
                    <div class="form-group">
                        <label>TOTP Secret (Base32)</label>
                        <input type="text" id="f-totp" value="${esc(existing?.totp_secret || '')}" placeholder="e.g. JBSWY3DPEHPK3PXP">
                    </div>
                    <div class="form-group">
                        <label>Tags (comma-separated)</label>
                        <input type="text" id="f-tags" value="${esc((existing?.tags || []).join(', '))}" placeholder="work, social, finance">
                    </div>
                    <div class="form-group">
                        <label>Notes</label>
                        <textarea id="f-notes" rows="3" placeholder="Optional notes...">${esc(existing?.notes || '')}</textarea>
                    </div>
                    <div class="form-actions">
                        <button type="button" class="btn btn-secondary" id="cancel-modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">${isEdit ? 'Save Changes' : 'Add Credential'}</button>
                    </div>
                </form>
            </div>
        `;

        document.body.appendChild(overlay);

        // Close on overlay click
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) overlay.remove();
        });

        overlay.querySelector('#cancel-modal').addEventListener('click', () => overlay.remove());

        // Password generator
        const genBtn = overlay.querySelector('#gen-btn');
        const genPreview = overlay.querySelector('#gen-preview');
        const genLengthSlider = overlay.querySelector('#gen-length');
        const genLengthVal = overlay.querySelector('#gen-length-val');
        const strengthFill = overlay.querySelector('#strength-fill');
        const strengthLabel = overlay.querySelector('#strength-label');
        const useGenBtn = overlay.querySelector('#use-gen-pw');

        genLengthSlider.addEventListener('input', () => {
            genLengthVal.textContent = genLengthSlider.value;
        });

        genBtn.addEventListener('click', async () => {
            try {
                const res = await api('POST', '/generate-password', {
                    length: parseInt(genLengthSlider.value),
                    uppercase: overlay.querySelector('#gen-upper').checked,
                    lowercase: overlay.querySelector('#gen-lower').checked,
                    digits: overlay.querySelector('#gen-digits').checked,
                    symbols: overlay.querySelector('#gen-symbols').checked,
                });
                genPassword = res.password;
                genStrength = res.strength;
                genPreview.textContent = genPassword;
                const pct = Math.min(100, (genStrength.entropy_bits / 120) * 100);
                strengthFill.style.width = pct + '%';
                strengthFill.className = 'fill strength-' + genStrength.level;
                strengthLabel.textContent = `${genStrength.level} (${Math.round(genStrength.entropy_bits)} bits)`;
            } catch (e) {
                showToast('Generate failed: ' + e.message, 'error');
            }
        });

        useGenBtn.addEventListener('click', () => {
            if (genPassword) {
                overlay.querySelector('#f-password').value = genPassword;
                showToast('Password applied');
            }
        });

        // Form submit
        overlay.querySelector('#cred-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const label = overlay.querySelector('#f-label').value.trim();
            const website = overlay.querySelector('#f-website').value.trim() || null;
            const username = overlay.querySelector('#f-username').value.trim() || null;
            const password = overlay.querySelector('#f-password').value;
            const totp_secret = overlay.querySelector('#f-totp').value.trim() || null;
            const notes = overlay.querySelector('#f-notes').value.trim() || null;
            const tagsStr = overlay.querySelector('#f-tags').value;
            const tags = tagsStr ? tagsStr.split(',').map(t => t.trim()).filter(Boolean) : [];

            try {
                if (isEdit) {
                    await api('PUT', `/credentials/${existing.id}`, {
                        label, website, username, password, totp_secret, notes, tags,
                    });
                    showToast('Credential updated');
                } else {
                    await api('POST', '/credentials', {
                        label, website, username, password, totp_secret, notes, tags,
                    });
                    showToast('Credential added');
                }
                overlay.remove();
                await loadCredentials();
                renderCredentialList();
                renderDetailPane();
            } catch (err) {
                showToast(err.message, 'error');
            }
        });
    }

    // -----------------------------------------------------------------------
    // Danger Mode — Master Password Verification + Timed Reveal
    // -----------------------------------------------------------------------
    function openDangerModeModal(credential) {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.innerHTML = `
            <div class="modal glass danger-modal">
                <h3>\u{1F6A8} Danger Mode</h3>
                <p style="font-size:14px;color:var(--text-secondary);margin-bottom:20px">Enter your master password to reveal this credential's password for 30 seconds.</p>
                <form id="danger-form">
                    <div class="form-group">
                        <label>Master Password</label>
                        <input type="password" id="danger-pw" placeholder="Enter master password" autocomplete="current-password" autofocus>
                    </div>
                    <p id="danger-error" style="color:var(--danger);font-size:13px;display:none;margin-bottom:12px"></p>
                    <div class="form-actions">
                        <button type="button" class="btn btn-secondary" id="danger-cancel">Cancel</button>
                        <button type="submit" class="btn btn-danger" id="danger-submit">\u{1F513} Reveal Password</button>
                    </div>
                </form>
            </div>
        `;
        document.body.appendChild(overlay);
        overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
        overlay.querySelector('#danger-cancel').addEventListener('click', () => overlay.remove());
        overlay.querySelector('#danger-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const pw = overlay.querySelector('#danger-pw').value;
            if (!pw) return;
            const btn = overlay.querySelector('#danger-submit');
            btn.disabled = true;
            btn.textContent = 'Verifying...';
            try {
                const res = await api('POST', '/auth/verify-password', { master_password: pw });
                if (res.valid) {
                    overlay.remove();
                    activateDangerMode(credential);
                } else {
                    overlay.querySelector('#danger-error').style.display = 'block';
                    overlay.querySelector('#danger-error').textContent = 'Invalid master password';
                    btn.disabled = false;
                    btn.textContent = '\u{1F513} Reveal Password';
                }
            } catch (err) {
                overlay.querySelector('#danger-error').style.display = 'block';
                overlay.querySelector('#danger-error').textContent = err.message;
                btn.disabled = false;
                btn.textContent = '\u{1F513} Reveal Password';
            }
        });
    }

    function activateDangerMode(credential) {
        if (dangerModeTimer) clearTimeout(dangerModeTimer);

        const card = document.querySelector('.detail-card');
        const fieldValue = document.getElementById('pw-field-value');
        const pwDisplay = document.getElementById('pw-display');
        const countdownWrap = document.getElementById('danger-countdown-wrap');

        if (!card || !pwDisplay) return;

        // Reveal password
        pwDisplay.innerHTML = `<span style="word-break:break-all;color:var(--danger)">${esc(credential.password)}</span>`;

        // Apply Danger Mode styling
        card.classList.add('danger-mode');
        if (fieldValue) fieldValue.classList.add('danger-field');

        // Show 30-second countdown SVG
        if (countdownWrap) {
            countdownWrap.style.display = 'flex';
            countdownWrap.innerHTML = `
                <div class="danger-timer">
                    <svg width="36" height="36" viewBox="0 0 36 36">
                        <circle cx="18" cy="18" r="15" fill="none" stroke="rgba(239,68,68,0.15)" stroke-width="2.5"/>
                        <circle cx="18" cy="18" r="15" fill="none" stroke="var(--danger)" stroke-width="2.5"
                            stroke-dasharray="94.25" stroke-dashoffset="0" stroke-linecap="round" id="danger-ring"
                            style="transition:stroke-dashoffset 1s linear;filter:drop-shadow(0 0 4px var(--danger))"/>
                    </svg>
                    <span class="danger-countdown-text" id="danger-seconds">30</span>
                </div>
            `;
        }

        let remaining = 30;
        const tickInterval = setInterval(() => {
            remaining--;
            const secEl = document.getElementById('danger-seconds');
            const ringEl = document.getElementById('danger-ring');
            if (secEl) secEl.textContent = remaining;
            if (ringEl) {
                const offset = ((30 - remaining) / 30) * 94.25;
                ringEl.setAttribute('stroke-dashoffset', offset.toString());
            }
            if (remaining <= 0) clearInterval(tickInterval);
        }, 1000);

        dangerModeTimer = setTimeout(() => {
            clearInterval(tickInterval);
            deactivateDangerMode();
        }, 30000);
    }

    function deactivateDangerMode() {
        if (dangerModeTimer) { clearTimeout(dangerModeTimer); dangerModeTimer = null; }

        const card = document.querySelector('.detail-card');
        const fieldValue = document.getElementById('pw-field-value');
        const pwDisplay = document.getElementById('pw-display');
        const countdownWrap = document.getElementById('danger-countdown-wrap');

        if (card) card.classList.remove('danger-mode');
        if (fieldValue) fieldValue.classList.remove('danger-field');
        if (pwDisplay) pwDisplay.innerHTML = '<span class="password-masked">\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022</span>';
        if (countdownWrap) { countdownWrap.style.display = 'none'; countdownWrap.innerHTML = ''; }
    }

    // -----------------------------------------------------------------------
    // Encryption Visualizer
    // -----------------------------------------------------------------------
    function renderVisualizer(container) {
        container.innerHTML = `
            <div class="visualizer-page">
                <div class="viz-header">
                    <h2>\u26A1 Encryption Pipeline</h2>
                    <p>Real-time visualization of the entropy-driven key derivation process</p>
                    <div class="viz-live-badge"><span class="viz-live-dot"></span> LIVE</div>
                </div>
                <div class="viz-pipeline">
                    <div class="viz-node glass" id="viz-frame-capture">
                        <div class="viz-node-icon">\u{1F4F9}</div>
                        <div class="viz-node-label">Frame Capture</div>
                        <div class="viz-node-detail" id="viz-source">Waiting...</div>
                        <div class="viz-scanlines"></div>
                    </div>
                    <div class="viz-connector"><div class="viz-particles"></div></div>

                    <div class="viz-node glass" id="viz-entropy-extract">
                        <div class="viz-node-icon">\u{1F9EC}</div>
                        <div class="viz-node-label">Entropy Extraction</div>
                        <div class="viz-node-detail viz-hex-flow" id="viz-hex-digits">SHA-256</div>
                    </div>
                    <div class="viz-connector"><div class="viz-particles"></div></div>

                    <div class="viz-node glass" id="viz-entropy-pool">
                        <div class="viz-node-icon">\u{1F4A7}</div>
                        <div class="viz-node-label">Entropy Pool</div>
                        <div class="viz-pool-slots" id="viz-pool-slots">
                            <div class="viz-slot"></div><div class="viz-slot"></div>
                            <div class="viz-slot"></div><div class="viz-slot"></div>
                            <div class="viz-slot"></div><div class="viz-slot"></div>
                            <div class="viz-slot"></div><div class="viz-slot"></div>
                        </div>
                        <div class="viz-node-detail" id="viz-pool-info">Depth: 0/8</div>
                    </div>
                    <div class="viz-connector"><div class="viz-particles"></div></div>

                    <div class="viz-node glass" id="viz-sys-mixer">
                        <div class="viz-node-icon">\u{1F300}</div>
                        <div class="viz-node-label">System Mixer</div>
                        <div class="viz-node-detail">OS Random + Traffic Entropy</div>
                        <div class="viz-mixer-ring"></div>
                    </div>
                    <div class="viz-connector"><div class="viz-particles"></div></div>

                    <div class="viz-node glass" id="viz-hkdf">
                        <div class="viz-node-icon">\u{1F517}</div>
                        <div class="viz-node-label">HKDF Key Derivation</div>
                        <div class="viz-node-detail" id="viz-epoch-info">Epoch: 0</div>
                        <div class="viz-chain-links">
                            <span class="viz-chain-link"></span>
                            <span class="viz-chain-link"></span>
                            <span class="viz-chain-link"></span>
                        </div>
                    </div>
                    <div class="viz-connector"><div class="viz-particles"></div></div>

                    <div class="viz-node glass viz-node-accent" id="viz-dek">
                        <div class="viz-node-icon">\u{1F511}</div>
                        <div class="viz-node-label">DEK Generation</div>
                        <div class="viz-node-detail viz-key-hex" id="viz-key-hex">0x0000...0000</div>
                    </div>
                    <div class="viz-connector"><div class="viz-particles"></div></div>

                    <div class="viz-node glass" id="viz-vault-enc">
                        <div class="viz-node-icon viz-lock-icon" id="viz-lock">\u{1F512}</div>
                        <div class="viz-node-label">Vault Encryption</div>
                        <div class="viz-node-detail">AES-256-GCM Sealed</div>
                    </div>
                </div>
                <div class="viz-stats">
                    <div class="viz-stat glass-sm">
                        <div class="viz-stat-value" id="viz-stat-epoch">—</div>
                        <div class="viz-stat-label">Key Epoch</div>
                    </div>
                    <div class="viz-stat glass-sm">
                        <div class="viz-stat-value" id="viz-stat-frames">—</div>
                        <div class="viz-stat-label">Frames Processed</div>
                    </div>
                    <div class="viz-stat glass-sm">
                        <div class="viz-stat-value" id="viz-stat-pool">—</div>
                        <div class="viz-stat-label">Pool Depth</div>
                    </div>
                    <div class="viz-stat glass-sm">
                        <div class="viz-stat-value" id="viz-stat-running">—</div>
                        <div class="viz-stat-label">Pipeline Status</div>
                    </div>
                </div>
            </div>
        `;
        startVisualizerPolling();
    }

    function startVisualizerPolling() {
        stopVisualizerPolling();
        let hexChars = '0123456789abcdef';
        let tick = 0;
        async function poll() {
            try {
                const snap = await api('GET', '/entropy-snapshot');
                tick++;

                // Update stats
                const epochEl = document.getElementById('viz-stat-epoch');
                const framesEl = document.getElementById('viz-stat-frames');
                const poolEl = document.getElementById('viz-stat-pool');
                const runningEl = document.getElementById('viz-stat-running');
                if (epochEl) epochEl.textContent = snap.key_epoch;
                if (framesEl) framesEl.textContent = snap.frames_processed;
                if (poolEl) poolEl.textContent = snap.pool_depth + '/8';
                if (runningEl) {
                    runningEl.textContent = snap.is_running ? 'ACTIVE' : 'STOPPED';
                    runningEl.style.color = snap.is_running ? 'var(--green-bright)' : 'var(--danger)';
                }

                // Update pipeline nodes
                const sourceEl = document.getElementById('viz-source');
                if (sourceEl) sourceEl.textContent = snap.entropy_source || (snap.has_traffic_entropy ? 'Traffic Stream' : 'OS Entropy');

                // Flowing hex digits
                const hexEl = document.getElementById('viz-hex-digits');
                if (hexEl) {
                    let fakeHash = '';
                    for (let i = 0; i < 16; i++) fakeHash += hexChars[Math.floor(Math.random() * 16)];
                    hexEl.textContent = fakeHash;
                }

                // Pool slots
                const slots = document.querySelectorAll('.viz-slot');
                slots.forEach((slot, i) => {
                    if (i < snap.pool_depth) {
                        slot.classList.add('filled');
                    } else {
                        slot.classList.remove('filled');
                    }
                });

                const poolInfo = document.getElementById('viz-pool-info');
                if (poolInfo) poolInfo.textContent = `Depth: ${snap.pool_depth}/8`;

                // Epoch info
                const epochInfo = document.getElementById('viz-epoch-info');
                if (epochInfo) epochInfo.textContent = `Epoch: ${snap.key_epoch}`;

                // Key hex
                const keyHex = document.getElementById('viz-key-hex');
                if (keyHex && snap.latest_key_hex) {
                    keyHex.textContent = snap.latest_key_hex;
                }

                // Animate lock icon
                const lockIcon = document.getElementById('viz-lock');
                if (lockIcon) {
                    lockIcon.classList.add('viz-lock-pulse');
                    setTimeout(() => lockIcon.classList.remove('viz-lock-pulse'), 500);
                }

                // Pulse nodes on update
                document.querySelectorAll('.viz-node').forEach((node, i) => {
                    setTimeout(() => {
                        node.classList.add('viz-node-active');
                        setTimeout(() => node.classList.remove('viz-node-active'), 600);
                    }, i * 80);
                });

            } catch {}
        }
        poll();
        visualizerInterval = setInterval(poll, 1000);
    }

    function stopVisualizerPolling() {
        if (visualizerInterval) {
            clearInterval(visualizerInterval);
            visualizerInterval = null;
        }
    }

    // -----------------------------------------------------------------------
    // Delete Confirmation
    // -----------------------------------------------------------------------
    function confirmDelete(credential) {
        const overlay = document.createElement('div');
        overlay.className = 'confirm-overlay';
        overlay.innerHTML = `
            <div class="confirm-box glass">
                <p>Delete <strong>${esc(credential.label)}</strong>?<br><span style="font-size:13px;color:var(--text-muted)">This cannot be undone.</span></p>
                <div class="confirm-actions">
                    <button class="btn btn-secondary" id="confirm-cancel">Cancel</button>
                    <button class="btn btn-danger" id="confirm-delete">Delete</button>
                </div>
            </div>
        `;
        document.body.appendChild(overlay);

        overlay.querySelector('#confirm-cancel').addEventListener('click', () => overlay.remove());
        overlay.querySelector('#confirm-delete').addEventListener('click', async () => {
            try {
                await api('DELETE', `/credentials/${credential.id}`);
                showToast('Credential deleted');
                selectedId = null;
                overlay.remove();
                await loadCredentials();
                renderCredentialList();
                renderDetailPane();
            } catch (err) {
                showToast(err.message, 'error');
                overlay.remove();
            }
        });
    }

    // -----------------------------------------------------------------------
    // Settings View
    // -----------------------------------------------------------------------
    function renderSettings(container) {
        container.innerHTML = `
            <div class="settings-page">
                <div class="settings-section glass">
                    <h3>\u{1F4E1} Live Streams</h3>
                    <p style="font-size:13px;color:var(--text-muted);margin-bottom:16px">Manage YouTube livestreams used for entropy harvesting. Frames are randomly picked from active streams to generate encryption keys.</p>
                    <div id="stream-list">Loading...</div>
                    <div style="margin-top:16px;display:flex;gap:8px">
                        <input type="text" id="new-stream-url" placeholder="YouTube livestream URL" style="flex:2">
                        <input type="text" id="new-stream-label" placeholder="Label" style="flex:1">
                        <button class="btn btn-primary" id="add-stream-btn" style="white-space:nowrap">Add Stream</button>
                    </div>
                </div>

                <div class="settings-section glass">
                    <h3>\u{1F512} Security</h3>
                    <div class="form-group" style="margin-bottom:0">
                        <label style="display:block;font-size:13px;color:var(--text-secondary);margin-bottom:8px">Auto-lock timeout (minutes)</label>
                        <div style="display:flex;align-items:center;gap:12px">
                            <input type="range" id="auto-lock-slider" min="1" max="30" value="5" style="flex:1">
                            <span id="auto-lock-val" style="font-size:16px;font-weight:600;color:var(--green-bright);min-width:30px;text-align:center">5</span>
                            <button class="btn btn-secondary" id="save-settings-btn" style="padding:8px 16px;font-size:13px">Save</button>
                        </div>
                    </div>
                </div>

                <div class="settings-section glass">
                    <h3>\u{1F4CA} Pipeline Status</h3>
                    <div id="pipeline-status" style="font-size:14px;color:var(--text-secondary)">Loading...</div>
                </div>
            </div>
        `;

        loadStreams();
        loadPipelineStatus();
        loadSettingsValues();

        const autoLockSlider = $('#auto-lock-slider');
        autoLockSlider.addEventListener('input', () => {
            $('#auto-lock-val').textContent = autoLockSlider.value;
        });

        $('#save-settings-btn').addEventListener('click', async () => {
            try {
                await api('PUT', '/settings', { auto_lock_minutes: parseInt(autoLockSlider.value) });
                showToast('Settings saved');
            } catch (e) {
                showToast(e.message, 'error');
            }
        });

        $('#add-stream-btn').addEventListener('click', async () => {
            const url = $('#new-stream-url').value.trim();
            const label = $('#new-stream-label').value.trim() || 'Stream';
            if (!url) return showToast('Enter a URL', 'error');
            try {
                $('#add-stream-btn').disabled = true;
                $('#add-stream-btn').textContent = 'Connecting...';
                await api('POST', '/streams', { url, label });
                showToast('Stream added');
                $('#new-stream-url').value = '';
                $('#new-stream-label').value = '';
                loadStreams();
            } catch (e) {
                showToast(e.message, 'error');
            } finally {
                const btn = $('#add-stream-btn');
                if (btn) {
                    btn.disabled = false;
                    btn.textContent = 'Add Stream';
                }
            }
        });
    }

    async function loadStreams() {
        try {
            const streams = await api('GET', '/streams');
            const listEl = $('#stream-list');
            if (!listEl) return;

            if (streams.length === 0) {
                listEl.innerHTML = '<p style="font-size:13px;color:var(--text-muted)">No streams configured. Add one below.</p>';
                return;
            }

            listEl.innerHTML = streams.map((s, i) => `
                <div class="stream-item">
                    <span class="status-dot ${s.status.toLowerCase()}"></span>
                    <div class="stream-info">
                        <div class="stream-label">${esc(s.label)}</div>
                        <div class="stream-url">${esc(s.url)}</div>
                    </div>
                    <span style="font-size:12px;color:var(--text-muted)">${s.frames_captured} frames</span>
                    <button class="btn btn-secondary btn-icon" data-edit="${i}" title="Edit">\u270F\uFE0F</button>
                    <button class="btn btn-danger btn-icon" data-remove="${i}" title="Remove">\u2715</button>
                </div>
            `).join('');

            listEl.querySelectorAll('[data-remove]').forEach(btn => {
                btn.addEventListener('click', async () => {
                    try {
                        await api('DELETE', `/streams/${btn.dataset.remove}`);
                        showToast('Stream removed');
                        loadStreams();
                    } catch (e) {
                        showToast(e.message, 'error');
                    }
                });
            });

            listEl.querySelectorAll('[data-edit]').forEach(btn => {
                btn.addEventListener('click', () => {
                    const idx = parseInt(btn.dataset.edit);
                    const s = streams[idx];
                    openEditStreamModal(idx, s);
                });
            });
        } catch (e) {
            const listEl = $('#stream-list');
            if (listEl) listEl.innerHTML = `<p style="color:var(--danger);font-size:13px">${e.message}</p>`;
        }
    }

    function openEditStreamModal(index, stream) {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.innerHTML = `
            <div class="modal glass">
                <h3>\u270F\uFE0F Edit Stream</h3>
                <form id="edit-stream-form">
                    <div class="form-group">
                        <label>Label</label>
                        <input type="text" id="es-label" value="${esc(stream.label)}" placeholder="Stream label">
                    </div>
                    <div class="form-group">
                        <label>URL</label>
                        <input type="text" id="es-url" value="${esc(stream.url)}" placeholder="YouTube livestream URL">
                    </div>
                    <div style="font-size:12px;color:var(--text-muted);margin-bottom:16px">
                        Status: <strong>${esc(stream.status)}</strong> &middot; ${stream.frames_captured} frames captured
                    </div>
                    <div class="form-actions">
                        <button type="button" class="btn btn-secondary" id="es-cancel">Cancel</button>
                        <button type="submit" class="btn btn-primary">Save Changes</button>
                    </div>
                </form>
            </div>
        `;
        document.body.appendChild(overlay);
        overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
        overlay.querySelector('#es-cancel').addEventListener('click', () => overlay.remove());
        overlay.querySelector('#edit-stream-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const label = overlay.querySelector('#es-label').value.trim();
            const url = overlay.querySelector('#es-url').value.trim();
            try {
                await api('PUT', `/streams/${index}`, { label: label || null, url: url || null });
                showToast('Stream updated');
                overlay.remove();
                loadStreams();
            } catch (err) {
                showToast(err.message, 'error');
            }
        });
    }

    async function loadPipelineStatus() {
        try {
            const status = await api('GET', '/status');
            const el = $('#pipeline-status');
            if (!el) return;
            el.innerHTML = `
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
                    <div class="glass-sm" style="padding:16px;text-align:center">
                        <div style="font-size:24px;font-weight:700;color:var(--green-bright)">${status.rotation.key_epoch}</div>
                        <div style="font-size:12px;color:var(--text-muted);margin-top:4px">Key Epoch</div>
                    </div>
                    <div class="glass-sm" style="padding:16px;text-align:center">
                        <div style="font-size:24px;font-weight:700;color:var(--green-bright)">${status.rotation.frames_processed}</div>
                        <div style="font-size:12px;color:var(--text-muted);margin-top:4px">Frames Processed</div>
                    </div>
                    <div class="glass-sm" style="padding:16px;text-align:center">
                        <div style="font-size:24px;font-weight:700;color:var(--green-bright)">${status.rotation.pool_depth}</div>
                        <div style="font-size:12px;color:var(--text-muted);margin-top:4px">Pool Depth</div>
                    </div>
                    <div class="glass-sm" style="padding:16px;text-align:center">
                        <div style="font-size:24px;font-weight:700;color:var(--green-bright)">${status.stream_count}</div>
                        <div style="font-size:12px;color:var(--text-muted);margin-top:4px">Active Streams</div>
                    </div>
                </div>
            `;
        } catch {}
    }

    async function loadSettingsValues() {
        try {
            const settings = await api('GET', '/settings');
            const slider = $('#auto-lock-slider');
            const val = $('#auto-lock-val');
            if (slider && val) {
                slider.value = settings.auto_lock_minutes;
                val.textContent = settings.auto_lock_minutes;
            }
        } catch {}
    }

    // -----------------------------------------------------------------------
    // Help View
    // -----------------------------------------------------------------------
    function renderHelp(container) {
        container.innerHTML = `
            <div class="help-page">
                <div style="text-align:center;margin-bottom:32px">
                    <div style="font-size:48px;filter:drop-shadow(0 0 20px var(--green-neon))">\u{1F6A6}</div>
                    <h2 style="font-size:24px;font-weight:700;background:linear-gradient(135deg,var(--green-bright),var(--green-glow));-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-top:8px">Traffic Cypher Guide</h2>
                    <p style="color:var(--text-muted);font-size:14px;margin-top:4px">Everything you need to know about your entropy-driven password manager</p>
                </div>

                <div class="help-section glass">
                    <h3>\u{1F510} What is Traffic Cypher?</h3>
                    <p>Traffic Cypher is a password manager that derives its encryption keys from the visual entropy of live YouTube video streams. Unlike traditional password managers that use a static encryption key, Traffic Cypher <strong>rotates the encryption key every second</strong> using frames captured from live traffic cameras or other livestreams.</p>
                    <p style="margin-top:8px">This means your vault is continuously re-encrypted with fresh cryptographic keys derived from real-world, unpredictable visual data combined with your master password.</p>
                </div>

                <div class="help-section glass">
                    <h3>\u{1F511} Getting Started</h3>
                    <ul>
                        <li><strong>Set a master password</strong> &mdash; The first time you unlock, your master password creates a new encrypted vault. Choose a strong, memorable password. This is the only thing you need to remember.</li>
                        <li><strong>Add credentials</strong> &mdash; Click the <code>+</code> button in the vault sidebar to add websites, usernames, and passwords. You can generate strong passwords using the built-in generator.</li>
                        <li><strong>Search &amp; browse</strong> &mdash; Use the search bar to quickly find credentials by name, username, website, or tag.</li>
                        <li><strong>Copy to clipboard</strong> &mdash; Click the <strong>Copy</strong> button next to any field. The clipboard is automatically cleared after 30 seconds for security.</li>
                    </ul>
                </div>

                <div class="help-section glass">
                    <h3>\u{1F3B2} Password Generator</h3>
                    <ul>
                        <li>Open the generator when adding or editing a credential</li>
                        <li>Adjust the <strong>length slider</strong> (8-64 characters)</li>
                        <li>Toggle character types: uppercase (ABC), lowercase (abc), digits (123), symbols (!@#)</li>
                        <li>The <strong>strength meter</strong> shows entropy in bits:
                            <ul>
                                <li><span style="color:var(--danger)">Weak</span> &mdash; under 40 bits</li>
                                <li><span style="color:var(--warning)">Fair</span> &mdash; 40-60 bits</li>
                                <li><span style="color:#3b82f6">Good</span> &mdash; 60-80 bits</li>
                                <li><span style="color:var(--green-glow)">Strong</span> &mdash; 80+ bits</li>
                            </ul>
                        </li>
                        <li>Click <strong>Use generated password</strong> to fill it into the form</li>
                    </ul>
                </div>

                <div class="help-section glass">
                    <h3>\u{1F551} Two-Factor Authentication (TOTP)</h3>
                    <ul>
                        <li>When adding a credential, paste a <strong>TOTP secret</strong> (Base32 encoded) into the TOTP Secret field</li>
                        <li>You can find this secret in your 2FA setup page (usually shown as a text code alongside the QR code)</li>
                        <li>Once saved, the credential detail view shows a <strong>live 6-digit code</strong> that refreshes every 30 seconds</li>
                        <li>A circular countdown timer shows remaining seconds</li>
                        <li>Click the code to copy it to your clipboard</li>
                    </ul>
                </div>

                <div class="help-section glass">
                    <h3>\u{1F4E1} Livestream Entropy Sources</h3>
                    <ul>
                        <li>Go to <strong>Settings</strong> to manage your livestream sources</li>
                        <li>The default stream is a live traffic camera that provides continuous visual entropy</li>
                        <li>You can <strong>add multiple streams</strong> for increased entropy diversity</li>
                        <li>The system <strong>randomly picks frames</strong> from different streams each second</li>
                        <li>If all streams go offline, the system falls back to OS-level entropy (still secure, but less unique)</li>
                        <li>Stream status is shown with colored indicators:
                            <ul>
                                <li><span style="color:var(--green-glow)">\u25CF Active</span> &mdash; stream is connected and providing frames</li>
                                <li><span style="color:var(--warning)">\u25CF Connecting</span> &mdash; resolving stream URL</li>
                                <li><span style="color:var(--danger)">\u25CF Failed</span> &mdash; stream connection failed</li>
                            </ul>
                        </li>
                    </ul>
                </div>

                <div class="help-section glass">
                    <h3>\u{1F504} Key Rotation</h3>
                    <ul>
                        <li>Every second, a new encryption key is derived from:
                            <ul>
                                <li>A randomly selected video frame from your livestream pool</li>
                                <li>SHA-256 entropy extraction (full-frame hash + spatial grid analysis)</li>
                                <li>A rolling pool of the last 8 frames of entropy</li>
                                <li>OS-level random data</li>
                                <li>The current timestamp</li>
                                <li>The previous key (cryptographic chaining via HKDF-SHA256)</li>
                            </ul>
                        </li>
                        <li>The vault is re-encrypted with the compound key: <code>HKDF(master_password, salt + traffic_key)</code></li>
                        <li>The <strong>Pipeline Status</strong> in Settings shows real-time key epoch, frames processed, and pool depth</li>
                        <li>The status bar at the bottom shows a green pulsing indicator when rotation is active</li>
                    </ul>
                </div>

                <div class="help-section glass">
                    <h3>\u{1F6E1}\uFE0F Security Features</h3>
                    <ul>
                        <li><strong>AES-256-GCM encryption</strong> &mdash; military-grade authenticated encryption for your vault</li>
                        <li><strong>HKDF-SHA256 key derivation</strong> &mdash; your master password is never stored; only used to derive keys</li>
                        <li><strong>Auto-lock</strong> &mdash; the vault locks after inactivity (configurable in Settings, default 5 minutes)</li>
                        <li><strong>Clipboard auto-clear</strong> &mdash; copied passwords are cleared from clipboard after 30 seconds</li>
                        <li><strong>Password history</strong> &mdash; when you change a password, the previous one is saved (up to 10)</li>
                        <li><strong>Local-only</strong> &mdash; your vault never leaves your machine. No cloud, no sync, no telemetry</li>
                        <li><strong>Localhost only</strong> &mdash; the web UI only binds to 127.0.0.1 and is not accessible from other machines</li>
                    </ul>
                </div>

                <div class="help-section glass">
                    <h3>\u{1F3F7}\uFE0F Tags &amp; Organization</h3>
                    <ul>
                        <li>Add <strong>tags</strong> to credentials for easy filtering (e.g., "work", "social", "finance")</li>
                        <li>Tags are entered as comma-separated values when adding or editing a credential</li>
                        <li>Use the search bar to filter by tag name</li>
                    </ul>
                </div>

                <div class="help-section glass">
                    <h3>\u2699\uFE0F Configuration</h3>
                    <ul>
                        <li><strong>Vault file</strong> &mdash; stored at <code>~/.traffic_cypher_vault.json</code></li>
                        <li><strong>Stream config</strong> &mdash; stored at <code>~/.traffic_cypher_streams.json</code></li>
                        <li><strong>Web UI</strong> &mdash; accessible at <code>http://127.0.0.1:9876</code></li>
                        <li><strong>Requirements</strong> &mdash; <code>ffmpeg</code> and <code>yt-dlp</code> must be installed for livestream entropy</li>
                    </ul>
                </div>

                <div class="help-section glass">
                    <h3>\u2753 FAQ</h3>
                    <ul>
                        <li><strong>What happens if the livestream goes offline?</strong><br>The system falls back to OS-level entropy. Your vault remains accessible and secure; you just lose the livestream-derived entropy component until the stream reconnects.</li>
                        <li><strong>Can I use any YouTube livestream?</strong><br>Yes, any active YouTube livestream works. Traffic cameras are ideal because they have constant visual variation.</li>
                        <li><strong>Is my master password stored anywhere?</strong><br>No. It is held in memory only while the vault is unlocked and cleared when you lock.</li>
                        <li><strong>Can someone decrypt my vault without the livestream?</strong><br>Your vault requires your master password to decrypt. The traffic key is an additional entropy layer stored alongside the encrypted vault, but without the master password it is useless.</li>
                    </ul>
                </div>
            </div>
        `;
    }

    // -----------------------------------------------------------------------
    // Data loading
    // -----------------------------------------------------------------------
    async function loadCredentials(query) {
        try {
            const q = query ? `?q=${encodeURIComponent(query)}` : '';
            credentials = await api('GET', `/credentials${q}`);
        } catch {
            credentials = [];
        }
    }

    // -----------------------------------------------------------------------
    // Status bar polling
    // -----------------------------------------------------------------------
    function startStatusPolling() {
        stopStatusPolling();
        statusInterval = setInterval(async () => {
            try {
                const status = await api('GET', '/status');
                const rotInfo = document.getElementById('rotation-info');
                const streamInfo = document.getElementById('stream-info');
                const entryCount = document.getElementById('entry-count');
                if (rotInfo) rotInfo.textContent = `Epoch: ${status.rotation.key_epoch}`;
                if (streamInfo) streamInfo.textContent = `Streams: ${status.stream_count} active`;
                if (entryCount) entryCount.textContent = `${status.entry_count} entries`;
            } catch {}
        }, 3000);
    }

    function stopStatusPolling() {
        if (statusInterval) {
            clearInterval(statusInterval);
            statusInterval = null;
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------
    function esc(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function getInitial(c) {
        return (c.label || '?')[0].toUpperCase();
    }

    function formatDate(ts) {
        if (!ts) return '—';
        return new Date(ts * 1000).toLocaleDateString('en-US', {
            year: 'numeric', month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit',
        });
    }

    // -----------------------------------------------------------------------
    // Init
    // -----------------------------------------------------------------------
    async function init() {
        // Check if already unlocked (e.g., page refresh)
        try {
            const status = await fetch(`${API}/auth/status`).then(r => r.json());
            if (!status.unlocked) {
                sessionToken = null;
            }
        } catch {}
        renderApp();
    }

    init();
})();
