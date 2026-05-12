'use strict';

const AppConfig = Object.freeze({
    COOKIE_NAME: 'user_pref_keyword',
    DATA_PATH: '/makanan.json',
    ALLOWED_SCHEMES: Object.freeze(['https:', 'http:']),
    MAX_COOKIE_LENGTH: 100,
    MAX_PARAM_LENGTH: 100,
    MAX_PARAMS: 20,           // [FIX #2] cap URL params processed
    MAX_FIELD_LENGTH: 512,    // [FIX #4] cap JSON field lengths
    FETCH_TIMEOUT_MS: 8000    // [FIX #5] fetch deadline
});

const ContentEngine = {
    escapeHTML(str) {
        if (typeof str !== 'string') return '';

        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;');
    },

    sanitizeURL(url) {
        if (typeof url !== 'string' || url.length > 2048) {
            return '#';
        }

        try {
            const parsed = new URL(url, window.location.origin);

            // allow only explicit safe protocols
            if (!AppConfig.ALLOWED_SCHEMES.includes(parsed.protocol)) {
                return '#';
            }

            // remove credentials
            parsed.username = '';
            parsed.password = '';

            return parsed.href;
        } catch {
            // allow only safe relative path
            if (
                /^\/(?!\/)/.test(url) ||
                /^\.\//.test(url)
            ) {
                return url;
            }

            return '#';
        }
    },

    getCookie() {
        try {
            const cookies = document.cookie ? document.cookie.split('; ') : [];

            for (const cookie of cookies) {
                const index = cookie.indexOf('=');

                if (index === -1) continue;

                const name = cookie.slice(0, index);

                if (name !== AppConfig.COOKIE_NAME) continue;

                const rawValue = cookie.slice(index + 1);

                const decoded = decodeURIComponent(rawValue);

                // [FIX #1] allow ':' in cookie values for consistency with sanitizeKeyword
                if (
                    typeof decoded !== 'string' ||
                    decoded.length > AppConfig.MAX_COOKIE_LENGTH ||
                    !/^[a-z0-9_:-]+$/i.test(decoded)
                ) {
                    return null;
                }

                return decoded;
            }

            return null;
        } catch {
            return null;
        }
    },

    setCookie(val) {
        // [FIX #1] allow ':' in cookie values for consistency with sanitizeKeyword
        if (
            typeof val !== 'string' ||
            val.length > AppConfig.MAX_COOKIE_LENGTH ||
            !/^[a-z0-9_:-]+$/i.test(val)
        ) {
            return;
        }

        const d = new Date();
        d.setTime(d.getTime() + (30 * 24 * 60 * 60 * 1000));

        document.cookie =
            `${AppConfig.COOKIE_NAME}=${encodeURIComponent(val)};` +
            `expires=${d.toUTCString()};` +
            'path=/;' +
            'SameSite=Lax;' +
            'Secure';
    },

    sanitizeKeyword(input) {
        if (typeof input !== 'string') return '';

        return input
            .toLowerCase()
            .slice(0, AppConfig.MAX_PARAM_LENGTH)
            .replace(/[^a-z0-9_:-]/g, '');
    },

    sanitizeDir(input) {
        if (typeof input !== 'string') return '';

        // [FIX #3] expanded blocklist — includes all built-in property names
        // that could cause unexpected prototype or object-method access
        const DANGEROUS_KEYS = new Set([
            '__proto__', 'prototype', 'constructor',
            'toString', 'valueOf', 'hasOwnProperty',
            'isPrototypeOf', 'propertyIsEnumerable',
            'toLocaleString', 'toJSON'
        ]);

        if (DANGEROUS_KEYS.has(input)) {
            return '';
        }

        return input
            .toLowerCase()
            .replace(/[^a-z0-9_-]/g, '')
            .slice(0, 50);
    },

    getURLContext() {
        const url = new URL(window.location.href);

        const pathSegments = url.pathname
            .split('/')
            .filter(Boolean);

        const activeDir = this.sanitizeDir(pathSegments[0] || '');

        const allParamValues = [];

        // [FIX #2] cap the number of URL parameters iterated to prevent DoS
        let paramCount = 0;

        url.searchParams.forEach((value) => {
            if (paramCount >= AppConfig.MAX_PARAMS) return;

            const cleaned = this.sanitizeKeyword(value);

            if (cleaned) {
                allParamValues.push(cleaned);
            }

            paramCount++;
        });

        return {
            activeDir,
            allParamValues
        };
    },

    validateDataStructure(data) {
        if (
            !data ||
            typeof data !== 'object' ||
            Array.isArray(data)
        ) {
            return false;
        }

        return true;
    },

    validateItem(item) {
        // [FIX #4] enforce maximum field lengths to prevent oversized payloads
        // from degrading rendering or bypassing downstream length expectations
        const MAX = AppConfig.MAX_FIELD_LENGTH;

        return (
            item &&
            typeof item === 'object' &&
            typeof item.keyword === 'string'     && item.keyword.length     <= MAX &&
            typeof item.title === 'string'       && item.title.length       <= MAX &&
            typeof item.description === 'string' && item.description.length <= MAX &&
            typeof item.link === 'string'        && item.link.length        <= MAX
        );
    },

    async init() {
        const { activeDir, allParamValues } = this.getURLContext();

        let existingCookie = this.getCookie();

        // [FIX #5] abort fetch if it exceeds the deadline
        const controller = new AbortController();
        const timeoutId = setTimeout(
            () => controller.abort(),
            AppConfig.FETCH_TIMEOUT_MS
        );

        try {
            const response = await fetch(AppConfig.DATA_PATH, {
                method: 'GET',
                credentials: 'same-origin',
                signal: controller.signal,
                headers: {
                    'Accept': 'application/json'
                }
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status}`);
            }

            // validate content-type
            const contentType = response.headers.get('content-type') || '';

            if (!contentType.includes('application/json')) {
                throw new Error('Invalid content type');
            }

            const allData = await response.json();

            if (!this.validateDataStructure(allData)) {
                throw new Error('Invalid JSON structure');
            }

            const keys = Object.keys(allData);

            if (keys.length === 0) {
                throw new Error('Empty data');
            }

            const defaultParentKey = keys[0];

            // safe property access
            const hasOwn = Object.prototype.hasOwnProperty.call(
                allData,
                activeDir
            );

            const rawContentGroup = hasOwn
                ? allData[activeDir]
                : allData[defaultParentKey];

            const contentGroup = Array.isArray(rawContentGroup)
                ? rawContentGroup.filter(item => this.validateItem(item))
                : [];

            let activeKeyword = existingCookie;

            // revalidate cookie against available keywords
            const availableKeywords = [
                ...new Set(
                    contentGroup.map(item =>
                        item.keyword.toLowerCase()
                    )
                )
            ];

            if (
                activeKeyword &&
                !availableKeywords.includes(activeKeyword.toLowerCase())
            ) {
                activeKeyword = null;
            }

            if (!activeKeyword && allParamValues.length > 0) {
                const foundMatch = allParamValues.find(val => {
                    return availableKeywords.some(
                        kw =>
                            kw !== 'default' &&
                            val.includes(kw)
                    );
                });

                if (foundMatch) {
                    const specificKw = availableKeywords.find(
                        kw => foundMatch.includes(kw)
                    );

                    const originalItem = contentGroup.find(
                        item =>
                            item.keyword.toLowerCase() === specificKw
                    );

                    if (
                        originalItem &&
                        typeof originalItem.keyword === 'string'
                    ) {
                        activeKeyword = originalItem.keyword;
                        this.setCookie(activeKeyword);
                    }
                }
            }

            activeKeyword = activeKeyword || 'default';

            let filtered = contentGroup.filter(item =>
                item.keyword.toLowerCase() ===
                activeKeyword.toLowerCase()
            );

            if (filtered.length === 0) {
                filtered = contentGroup.filter(
                    item => item.keyword === 'default'
                );
            }

            this.render(filtered, activeKeyword);

        } catch (err) {
            clearTimeout(timeoutId);
            console.error('ContentEngine Error:', err);
        }
    },

    render(items, activeKey) {
        const root = document.getElementById('recommendation-engine');

        if (!root) return;

        // avoid innerHTML injection
        root.textContent = '';

        const header = document.createElement('div');
        header.className = 'rec-header';
        header.textContent = `Rekomendasi: ${activeKey}`;

        root.appendChild(header);

        const ul = document.createElement('ul');
        ul.className = 'item-list';

        items.forEach(item => {
            const li = document.createElement('li');
            li.className = 'item-card';

            const a = document.createElement('a');
            a.href = this.sanitizeURL(item.link);
            a.className = 'item-link';
            a.textContent = item.title;

            // security hardening
            a.rel = 'noopener noreferrer';

            const parsedUrl = (() => {
                try {
                    return new URL(a.href, window.location.origin);
                } catch {
                    return null;
                }
            })();

            // optional:
            // external link opens new tab safely
            if (
                parsedUrl &&
                parsedUrl.origin !== window.location.origin
            ) {
                a.target = '_blank';
            }

            const p = document.createElement('p');
            p.className = 'item-desc';
            p.textContent = item.description;

            li.appendChild(a);
            li.appendChild(p);

            ul.appendChild(li);
        });

        root.appendChild(ul);
    }
};

document.addEventListener('DOMContentLoaded', () => {
    ContentEngine.init();
});
