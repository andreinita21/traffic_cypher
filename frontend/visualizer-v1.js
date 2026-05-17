// Traffic Cypher — Visualizer v1 (ARCHIVED)
// ============================================================================
// This file is a frozen, verbatim archive of the v1 Encryption Pipeline
// visualizer that shipped before Visualizer v2.
//
//   - It is NOT loaded by index.html.
//   - It is NOT routed by the backend.
//   - It is a dead reference file, kept only so the original implementation
//     (and its honestly-labelled FAKE bits — see VISUALIZER.md) can be
//     consulted without digging through git history.
//
// The v1 functions below were extracted VERBATIM from frontend/app.js. They
// depend on the SPA's `api()` helper and the `visualizerInterval` module
// variable, neither of which exist in this standalone file — so this file is
// intentionally non-functional on its own. Do not wire it back up.
// ============================================================================

/* eslint-disable */

function renderVisualizer(container) {
    container.innerHTML = `
        <div class="visualizer-page">
            <div class="viz-header">
                <h2>⚡ Encryption Pipeline</h2>
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
