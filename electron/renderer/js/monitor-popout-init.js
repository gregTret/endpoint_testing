// Popout window bootstrap. Kept as an external file (not inline) so it is
// allowed under the window's CSP (default-src 'self' blocks inline scripts).
document.addEventListener('DOMContentLoaded', () => {
    if (window.ResponseMonitor) window.ResponseMonitor.init();
});
