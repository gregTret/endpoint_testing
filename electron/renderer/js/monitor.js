/**
 * ResponseMonitor — pings a target URL at a configurable interval and
 * graphs response times on a canvas.
 *
 * Two modes, both fully self-sufficient:
 *   1. Main window tab — pings via fetch, draws graph
 *   2. Popout window   — pings via fetch, draws graph (independent)
 */
window.ResponseMonitor = (function () {
    const API = 'http://127.0.0.1:8000/api';
    const DEFAULT_INTERVAL = 1.0;
    const DEFAULT_TIMEOUT  = 15;
    const MAX_POINTS       = 1000;

    let running    = false;
    let timer      = null;
    let poppedOut  = false;
    let dataPoints = [];

    let urlInput, intervalInput, timeoutInput, toggleBtn, statusSpan, canvas, ctx, latestDiv;
    let popOutBtn, overlay;

    const isPopout = typeof window.monitorAPI !== 'undefined';

    // ── init ────────────────────────────────────────────────────────

    function init() {
        urlInput      = document.getElementById('monitor-url');
        intervalInput = document.getElementById('monitor-interval');
        timeoutInput  = document.getElementById('monitor-timeout');
        toggleBtn     = document.getElementById('btn-monitor-toggle');
        statusSpan    = document.getElementById('monitor-status');
        canvas        = document.getElementById('monitor-canvas');
        latestDiv     = document.getElementById('monitor-latest');
        ctx           = canvas.getContext('2d');

        // Both modes: clicking toggle starts/stops the local pinger
        toggleBtn.addEventListener('click', toggle);

        if (isPopout) {
            // Receive initial config from main window
            window.monitorAPI.onConfig((config) => {
                if (config.url)      urlInput.value      = config.url;
                if (config.interval) intervalInput.value  = config.interval;
                if (config.timeout)  timeoutInput.value   = config.timeout;
                if (config.running)  start();
            });

            // Receive URL updates pushed from main (e.g. "Send to Monitor")
            window.monitorAPI.onConfigUpdate((config) => {
                if (config.url)      urlInput.value      = config.url;
                if (config.interval) intervalInput.value  = config.interval;
                if (config.timeout)  timeoutInput.value   = config.timeout;
            });
        } else {
            initMainWindow();
        }
    }

    function initMainWindow() {
        if (typeof SendTo !== 'undefined') {
            SendTo.register('monitor', {
                label: 'Monitor',
                receive(data) {
                    const url = data.url || data.target_url || '';
                    if (url) {
                        urlInput.value = url;
                        // If popped out, push URL to popout window and focus it
                        if (poppedOut && window.electronAPI) {
                            window.electronAPI.sendMonitorConfig({ url: url });
                            window.electronAPI.focusMonitorWindow();
                        }
                    }
                },
            });
        }

        popOutBtn = document.getElementById('btn-monitor-popout');
        if (popOutBtn) popOutBtn.addEventListener('click', popOut);
        overlay = document.getElementById('monitor-popout-overlay');

        if (window.electronAPI && window.electronAPI.onMonitorWindowClosed) {
            window.electronAPI.onMonitorWindowClosed(() => {
                poppedOut = false;
                if (overlay) overlay.classList.add('hidden');
                if (popOutBtn) popOutBtn.disabled = false;
            });
        }
    }

    // ── pop out ─────────────────────────────────────────────────────

    function popOut() {
        if (poppedOut || isPopout) return;
        if (!window.electronAPI || !window.electronAPI.popOutMonitor) return;

        window.electronAPI.popOutMonitor({
            url:      (urlInput.value || '').trim(),
            interval: parseFloat(intervalInput.value) || DEFAULT_INTERVAL,
            timeout:  parseFloat(timeoutInput.value) || DEFAULT_TIMEOUT,
            running:  running,
        });

        poppedOut = true;
        // The popout now owns the pinger — stop the main-window loop so we
        // don't double-poll the target (and the backend) for the whole session.
        if (running) stop();
        if (overlay) overlay.classList.remove('hidden');
        if (popOutBtn) popOutBtn.disabled = true;
    }

    // ── start / stop ────────────────────────────────────────────────

    function toggle() {
        if (running) stop(); else start();
    }

    function start() {
        const url = (urlInput.value || '').trim();
        if (!url) { urlInput.focus(); return; }
        running = true;
        toggleBtn.textContent = 'Stop Monitor';
        toggleBtn.classList.add('monitor-btn-active');
        statusSpan.textContent = 'Running';
        statusSpan.className = 'monitor-status-badge monitor-running';
        schedulePing();
    }

    function stop() {
        running = false;
        if (timer) { clearTimeout(timer); timer = null; }
        toggleBtn.textContent = 'Start Monitor';
        toggleBtn.classList.remove('monitor-btn-active');
        statusSpan.textContent = 'Stopped';
        statusSpan.className = 'monitor-status-badge';
    }

    // ── ping loop ───────────────────────────────────────────────────

    function schedulePing() {
        if (!running) return;
        doPing().then(() => {
            if (!running) return;
            const interval = Math.max(0.5, parseFloat(intervalInput.value) || DEFAULT_INTERVAL);
            timer = setTimeout(schedulePing, interval * 1000);
        });
    }

    async function doPing() {
        const url     = (urlInput.value || '').trim();
        const timeout = Math.max(1, parseFloat(timeoutInput.value) || DEFAULT_TIMEOUT);
        if (!url) { stop(); return; }

        try {
            const res  = await fetch(`${API}/monitor/ping?url=${encodeURIComponent(url)}&timeout=${timeout}`);
            const data = await res.json();
            addPoint(data);
        } catch (e) {
            addPoint({ status_code: null, response_time_ms: null, error: 'Fetch failed: ' + e.message });
        }
    }

    function addPoint(data) {
        const pt = {
            timestamp:        Date.now(),
            status_code:      data.status_code,
            response_time_ms: data.response_time_ms,
            error:            data.error,
        };
        dataPoints.push(pt);
        if (dataPoints.length > MAX_POINTS) dataPoints.shift();

        updateLatest(pt);

        // In popout: always draw. In main window: only if tab visible.
        if (isPopout) {
            drawGraph();
        } else {
            const pane = canvas.closest('.tab-pane');
            if (pane && pane.classList.contains('active')) drawGraph();
        }
    }

    // ── latest status line ──────────────────────────────────────────

    function updateLatest(pt) {
        if (!latestDiv) return;
        const time = new Date(pt.timestamp).toLocaleTimeString();
        if (pt.error) {
            latestDiv.className = 'monitor-latest monitor-latest-err';
            latestDiv.textContent = `${time}  —  ERROR: ${pt.error}`;
        } else if (pt.status_code >= 500) {
            latestDiv.className = 'monitor-latest monitor-latest-err';
            latestDiv.textContent = `${time}  —  ${pt.status_code}  ${pt.response_time_ms}ms`;
        } else if (pt.status_code >= 300) {
            latestDiv.className = 'monitor-latest monitor-latest-warn';
            latestDiv.textContent = `${time}  —  ${pt.status_code}  ${pt.response_time_ms}ms`;
        } else {
            latestDiv.className = 'monitor-latest monitor-latest-ok';
            latestDiv.textContent = `${time}  —  ${pt.status_code}  ${pt.response_time_ms}ms`;
        }
    }

    // ── canvas graph ────────────────────────────────────────────────

    function drawGraph() {
        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.parentElement.getBoundingClientRect();
        const w = Math.floor(rect.width);
        const h = Math.floor(rect.height);
        if (w < 10 || h < 10) return;

        canvas.width  = w * dpr;
        canvas.height = h * dpr;
        canvas.style.width  = w + 'px';
        canvas.style.height = h + 'px';
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

        const pad = { top: 30, right: 20, bottom: 32, left: 55 };
        const gw = w - pad.left - pad.right;
        const gh = h - pad.top - pad.bottom;

        ctx.fillStyle = '#0d1117';
        ctx.fillRect(0, 0, w, h);

        if (dataPoints.length < 2) {
            ctx.fillStyle = '#8b949e';
            ctx.font = '12px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText(dataPoints.length === 0 ? 'No data yet — start monitoring to see response times' : 'Waiting for more data...', w / 2, h / 2);
            return;
        }

        let maxMs = 500;
        for (const pt of dataPoints) {
            if (pt.response_time_ms != null && pt.response_time_ms > maxMs) maxMs = pt.response_time_ms;
        }
        maxMs = niceMax(maxMs);

        const t0 = dataPoints[0].timestamp;
        const t1 = dataPoints[dataPoints.length - 1].timestamp;
        const tRange = Math.max(t1 - t0, 1);

        function xPos(ts) { return pad.left + ((ts - t0) / tRange) * gw; }
        function yPos(ms) { return pad.top + gh - (ms / maxMs) * gh; }

        ctx.strokeStyle = '#21262d';
        ctx.lineWidth = 1;
        const ySteps = 5;
        ctx.font = '10px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';
        ctx.fillStyle = '#8b949e';
        ctx.textAlign = 'right';
        for (let i = 0; i <= ySteps; i++) {
            const ms = (maxMs / ySteps) * i;
            const y = yPos(ms);
            ctx.beginPath();
            ctx.moveTo(pad.left, y);
            ctx.lineTo(w - pad.right, y);
            ctx.stroke();
            ctx.fillText(ms >= 1000 ? (ms / 1000).toFixed(1) + 's' : Math.round(ms) + 'ms', pad.left - 6, y + 3);
        }

        ctx.textAlign = 'center';
        const xLabelCount = Math.min(6, dataPoints.length);
        for (let i = 0; i < xLabelCount; i++) {
            const idx = Math.floor((i / (xLabelCount - 1)) * (dataPoints.length - 1));
            const pt = dataPoints[idx];
            ctx.fillText(new Date(pt.timestamp).toLocaleTimeString(), xPos(pt.timestamp), h - pad.bottom + 16);
        }

        const segments = [];
        for (let i = 0; i < dataPoints.length; i++) {
            const pt = dataPoints[i];
            const ms = pt.response_time_ms != null ? pt.response_time_ms : 0;
            segments.push({ x: xPos(pt.timestamp), y: yPos(ms), color: pointColor(pt), pt, ms });
        }

        ctx.beginPath();
        ctx.moveTo(segments[0].x, yPos(0));
        for (const s of segments) ctx.lineTo(s.x, s.y);
        ctx.lineTo(segments[segments.length - 1].x, yPos(0));
        ctx.closePath();
        ctx.fillStyle = 'rgba(88, 166, 255, 0.08)';
        ctx.fill();

        ctx.lineWidth = 1.5;
        for (let i = 1; i < segments.length; i++) {
            ctx.beginPath();
            ctx.strokeStyle = segments[i].color;
            ctx.moveTo(segments[i - 1].x, segments[i - 1].y);
            ctx.lineTo(segments[i].x, segments[i].y);
            ctx.stroke();
        }

        for (const s of segments) {
            if (s.pt.error || (s.pt.status_code && s.pt.status_code >= 500)) {
                ctx.beginPath();
                ctx.arc(s.x, s.y, 3.5, 0, Math.PI * 2);
                ctx.fillStyle = '#f85149';
                ctx.fill();
            }
        }

        const validPts = dataPoints.filter(p => p.response_time_ms != null);
        const avg = validPts.length > 0 ? validPts.reduce((s, p) => s + p.response_time_ms, 0) / validPts.length : 0;
        const errCount = dataPoints.filter(p => p.error || (p.status_code && p.status_code >= 500)).length;

        ctx.fillStyle = 'rgba(13, 17, 23, 0.75)';
        ctx.fillRect(pad.left + 6, pad.top + 4, 175, 48);
        ctx.font = '11px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';
        ctx.fillStyle = '#c9d1d9';
        ctx.textAlign = 'left';
        ctx.fillText(`Avg: ${avg.toFixed(1)}ms   Points: ${dataPoints.length}`, pad.left + 12, pad.top + 20);
        ctx.fillStyle = errCount > 0 ? '#f85149' : '#3fb950';
        ctx.fillText(`Errors: ${errCount}`, pad.left + 12, pad.top + 38);
    }

    function pointColor(pt) {
        if (pt.error) return '#f85149';
        if (!pt.status_code) return '#f85149';
        if (pt.status_code >= 500) return '#f85149';
        if (pt.status_code >= 300) return '#d29922';
        return '#3fb950';
    }

    function niceMax(val) {
        const mag = Math.pow(10, Math.floor(Math.log10(val)));
        const norm = val / mag;
        if (norm <= 1)   return mag;
        if (norm <= 2)   return 2 * mag;
        if (norm <= 5)   return 5 * mag;
        return 10 * mag;
    }

    function onTabVisible() {
        if (canvas && dataPoints.length > 0) drawGraph();
    }

    return { init, onTabVisible };
})();
