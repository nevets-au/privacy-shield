// ==UserScript==
// @name         PrivacyShield
// @namespace    https://github.com/combined/privacy-shield
// @version      2.1.0
// @description  Comprehensive privacy tool for Edge/Chrome: strips tracking tokens from URLs in real-time, blocks referrer leakage, cleans all stored site data on demand, and unregisters tracking service workers.
// @author       Combined & extended from works by Will Huang & ChiamZhang
// @license      MIT
// @match        *://*/*
// @grant        GM_registerMenuCommand
// @grant        GM_unregisterMenuCommand
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_openInTab
// @run-at       document-start
// ==/UserScript==

(function () {
    'use strict';

    // =========================================================================
    // CONFIG — tweak behaviour here without touching the rest of the script
    // =========================================================================

    const CONFIG = {
        whitelist: {},
        pollDuration: 2000,
        pollInterval: 500,
        toastDuration: 3500,
    };

    // =========================================================================
    // SECTION 1 — REFERRER SUPPRESSION
    // =========================================================================

    (function disablePrefetch() {
        const meta = document.createElement('meta');
        meta.httpEquiv = 'x-dns-prefetch-control';
        meta.content = 'off';
        (document.head || document.documentElement).appendChild(meta);
    })();

    (function suppressReferrer() {
        try {
            const meta    = document.createElement('meta');
            meta.name     = 'referrer';
            meta.content  = 'no-referrer';
            const target  = document.head || document.documentElement;
            if (target) target.insertBefore(meta, target.firstChild);
        } catch (e) { /* Best-effort — silent fail */ }
    })();

    // =========================================================================
    // SECTION 1.5 — API NEUTRALIZATION
    // =========================================================================

    if (navigator && 'sendBeacon' in navigator) {
        navigator.sendBeacon = () => false;
    }

    if (navigator.getBattery) {
        navigator.getBattery = () => Promise.resolve({ charging: true, level: 1, onchargingchange: null, onlevelchange: null, onchargingtimechange: null, ondischargingtimechange: null });
    }

    if (navigator.connection) {
        try {
            Object.defineProperty(navigator, 'connection', {
                get: () => undefined,
                configurable: false
            });
        } catch (e) { /* Some browsers restrict this */ }
    }

    // =========================================================================
    // SECTION 2 — TRACKING TOKEN STRIPPER
    // =========================================================================

    const _origReplaceState = history.replaceState.bind(history);

    history.replaceState = function replaceState() {
        try {
            const ret = _origReplaceState.apply(this, arguments);
            window.dispatchEvent(new Event('replacestate'));
            window.dispatchEvent(new Event('locationchange'));
            return ret;
        } catch (e) {
            window.dispatchEvent(new Event('locationchange'));
            return _origReplaceState.apply(this, arguments);
        }
    };

    window.addEventListener('popstate', () => {
        window.dispatchEvent(new Event('locationchange'));
    });

    window.addEventListener('locationchange', stripTrackingTokens);
    stripTrackingTokens();

    const _pollId = setInterval(stripTrackingTokens, CONFIG.pollInterval);
    setTimeout(() => clearInterval(_pollId), CONFIG.pollDuration);

    class TokenStripper {
        constructor(url) {
            this.parsed = new URL(url);
        }

        remove(name, value) {
            const guarded = CONFIG.whitelist[name] || [];
            if (guarded.some(d => this.parsed.hostname.endsWith(d))) return this;

            if (this.parsed.searchParams.has(name)) {
                if (value === undefined || value === this.parsed.searchParams.get(name)) {
                    this.parsed.searchParams.delete(name);
                }
            }
            return this;
        }

        removeByDomain(domain, name) {
            if (this.parsed.hostname.toLowerCase() !== domain.toLowerCase()) return this;
            const [key, val] = name.split('=', 2);
            return this.remove(key, val);
        }

        toString() { return this.parsed.toString(); }
    }

    function stripTrackingTokens() {
        const STRIP_EXCLUDED_DOMAINS = [
            'icloud.com',
            'www.icloud.com',
        ];
        if (STRIP_EXCLUDED_DOMAINS.some(d => location.hostname.endsWith(d))) return;

        try {
            const cleaned = new TokenStripper(location.href)

                // ── Facebook ──────────────────────────────────────────────────
                .remove('fbclid')
                .removeByDomain('www.facebook.com', 'privacy_mutation_token')
                .removeByDomain('www.facebook.com', 'acontext')
                .removeByDomain('www.facebook.com', '__xts__[0]')
                .removeByDomain('www.facebook.com', 'notif_t')
                .removeByDomain('www.facebook.com', 'notif_id')
                .removeByDomain('www.facebook.com', 'notif_ids[0]')
                .removeByDomain('www.facebook.com', 'notif_ids[1]')
                .removeByDomain('www.facebook.com', 'notif_ids[2]')
                .removeByDomain('www.facebook.com', 'notif_ids[3]')
                .removeByDomain('www.facebook.com', 'ref', 'notif')
                .removeByDomain('www.facebook.com', 'ref=watch_permalink')

                // ── Dropbox ───────────────────────────────────────────────────
                .removeByDomain('www.dropbox.com', '_ad')
                .removeByDomain('www.dropbox.com', '_camp')
                .removeByDomain('www.dropbox.com', '_tk')

                // ── YouTube ───────────────────────────────────────────────────
                .removeByDomain('youtu.be', 'si')
                .removeByDomain('www.youtube.com', 'si')

                // ── TikTok ────────────────────────────────────────────────────
                .remove('ttclid')

                // ── Twitter / X ───────────────────────────────────────────────
                .remove('twclid')

                // ── Reddit Ads ────────────────────────────────────────────────
                .remove('rdt_cid')

                // ── Pinterest ─────────────────────────────────────────────────
                .remove('epik')

                // ── LinkedIn ──────────────────────────────────────────────────
                .remove('li_fat_id')
                .remove('trk')
                .remove('trkCampaign')

                // ── Google Analytics (standard UTM + client IDs) ─────────────
                .remove('utm_id')
                .remove('utm_source')
                .remove('utm_medium')
                .remove('utm_campaign')
                .remove('utm_term')
                .remove('utm_content')
                .remove('_ga')
                .remove('gclid')
                .remove('gclsrc')
                .remove('_gl')

                // ── Extended UTM variants ──────────────────────────────────────
                .remove('utm_campaignid')
                .remove('utm_cid')
                .remove('utm_reader')
                .remove('utm_referrer')
                .remove('utm_name')
                .remove('utm_social')
                .remove('utm_social-type')

                // ── Adobe Analytics / Omniture ───────────────────────────────
                .remove('s_cid')
                .remove('s_kwcid')
                .remove('s_src')
                .remove('ef_id')

                // ── Microsoft Ads ─────────────────────────────────────────────
                .remove('msclkid')
                .remove('mcid')
                .remove('wt.mc_id')

                // ── Microsoft properties ──────────────────────────────────────
                .removeByDomain('devblogs.microsoft.com', 'utm_issue')
                .removeByDomain('devblogs.microsoft.com', 'utm_position')
                .removeByDomain('devblogs.microsoft.com', 'utm_topic')
                .removeByDomain('devblogs.microsoft.com', 'utm_section')
                .removeByDomain('devblogs.microsoft.com', 'utm_cta')
                .removeByDomain('devblogs.microsoft.com', 'utm_description')
                .removeByDomain('devblogs.microsoft.com', 'ocid')
                .removeByDomain('learn.microsoft.com', 'ocid')
                .removeByDomain('learn.microsoft.com', 'redirectedfrom')
                .removeByDomain('azure.microsoft.com', 'OCID')
                .removeByDomain('azure.microsoft.com', 'ef_id')
                .removeByDomain('www.msn.com', 'ocid')
                .removeByDomain('www.msn.com', 'cvid')
                .removeByDomain('bing.com', 'ocid')
                .removeByDomain('www.bing.com', 'ocid')
                .removeByDomain('www.bing.com', 'cvid')
                .removeByDomain('www.bing.com', 'setlang')
                .removeByDomain('news.microsoft.com', 'ocid')
                .removeByDomain('support.microsoft.com', 'ocid')
                .removeByDomain('blogs.microsoft.com', 'ocid')
                .removeByDomain('techcommunity.microsoft.com', 'ocid')

                // ── Instagram ─────────────────────────────────────────────────
                .remove('igshid')

                // ── HubSpot ───────────────────────────────────────────────────
                .remove('_hsenc')
                .remove('_hsmi')
                .remove('__hstc')
                .remove('__hssc')
                .remove('__hsfp')

                // ── Marketo ───────────────────────────────────────────────────
                .remove('mkt_tok')

                // ── Mailchimp ─────────────────────────────────────────────────
                .remove('mc_cid')
                .remove('mc_eid')
                .remove('goal')

                // ── Yandex ────────────────────────────────────────────────────
                .remove('yclid')
                .remove('_openstat')

                // ── SendGrid ──────────────────────────────────────────────────
                .remove('mc')
                .remove('mcd')
                .remove('cvosrc')

                // ── SC (Sales Cloud / various CRM platforms) ─────────────────
                .remove('sc_channel')
                .remove('sc_campaign')
                .remove('sc_geo')
                .remove('sc_publisher')
                .remove('sc_outcome')
                .remove('sc_country')

                // ── Bilibili ──────────────────────────────────────────────────
                .removeByDomain('www.bilibili.com', 'share_source')
                .removeByDomain('www.bilibili.com', 'share_medium')

                // ── Zendesk ────────────────────────────────────────────────────
                .remove('zanpid')

                // ── Ometria ───────────────────────────────────────────────────
                .remove('oly_enc_id')
                .remove('oly_anon_id')

                // ── Klaviyo ────────────────────────────────────────────────────
                .remove('__s')
                .remove('_ke')

                // ── Additional trackers ───────────────────────────────────────
                .remove('redirect_log_mongo_id')
                .remove('redirect_mongo_id')
                .remove('fb_action_ids')
                .remove('fb_action_types')
                .remove('fb_source')
                .remove('fb_ref')
                .remove('action_object_map')
                .remove('action_type_map')
                .remove('action_ref_map')
                .remove('vero_conv')
                .remove('vero_id')
                .remove('wickedid')
                .remove('wt_mc')
                .remove('s_kwcid')
                .remove('ml_subscriber')
                .remove('ml_subscriber_hash')
                .remove('trk_contact')
                .remove('trk_msg')
                .remove('trk_module')
                .remove('trk_sid')
                .remove('gdftrk')
                .remove('gdfms')
                .remove('gdffi')

                // ── Misc ──────────────────────────────────────────────────────
                .remove('__tn__')
                .remove('itm_source')
                .remove('itm_medium')
                .remove('itm_campaign')
                .remove('cr_cc')
                .remove('guce_referrer')
                .remove('guce_referrer_sig')

                .toString();

            if (cleaned && location.href !== cleaned) {
                const before = new URL(location.href).searchParams;
                const after  = new URL(cleaned).searchParams;
                for (const key of before.keys()) {
                    if (!after.has(key)) _sessionStats.tokensStripped++;
                }
                _origReplaceState.call(history, {}, '', cleaned);
            }
        } catch (e) {
            // Swallow errors for non-http(s) URLs
        }
    }

    // =========================================================================
    // SECTION 3 — URL FRAGMENT (#) TRACKER CLEANER
    // =========================================================================

    const HASH_TRACKING_PATTERNS = [
        /[#&]fbclid=[^&]*/g,
        /[#&]_hsenc=[^&]*/g,
        /[#&]mkt_tok=[^&]*/g,
    ];

    function stripHashTokens() {
        try {
            const hash = location.hash;
            if (!hash) return;

            let cleaned = hash;
            HASH_TRACKING_PATTERNS.forEach(re => { cleaned = cleaned.replace(re, ''); });
            cleaned = cleaned.replace(/^#+/, '#').replace(/[#&]+$/, '');

            if (cleaned !== hash) {
                const newUrl = location.href.replace(hash, cleaned === '#' ? '' : cleaned);
                _origReplaceState.call(history, {}, '', newUrl);
                _sessionStats.tokensStripped++;
            }
        } catch (e) { /* Silent fail */ }
    }

    window.addEventListener('hashchange', stripHashTokens);
    stripHashTokens();

    // =========================================================================
    // SECTION 4 — PERFORMANCE API CLEANUP
    // =========================================================================

    if (window.performance) {
        if (typeof performance.clearResourceTimings === 'function') {
            performance.clearResourceTimings();
        }
        if (typeof performance.clearMeasures === 'function') {
            performance.clearMeasures();
        }
    }

    // =========================================================================
    // SECTION 5 — SESSION STATISTICS
    // =========================================================================

    const _sessionStats = {
        tokensStripped:   0,
        clearsPerformed:  0,
    };

    // =========================================================================
    // SECTION 6 — SITE DATA CLEANER
    // =========================================================================

    function clearLocalStorage() {
        try {
            localStorage.clear();
            console.log('[PrivacyShield] localStorage cleared.');
            return true;
        } catch (e) {
            console.error('[PrivacyShield] localStorage clear failed:', e);
            return false;
        }
    }

    function clearSessionStorage() {
        try {
            sessionStorage.clear();
            console.log('[PrivacyShield] sessionStorage cleared.');
            return true;
        } catch (e) {
            console.error('[PrivacyShield] sessionStorage clear failed:', e);
            return false;
        }
    }

    function clearCookies() {
        try {
            const hostname = window.location.hostname;
            const expired = 'expires=Thu, 01 Jan 1970 00:00:00 UTC';
            const cookies = document.cookie.split(';').filter(c => c.trim());

            cookies.forEach(cookie => {
                const name = cookie.split('=')[0].trim();
                document.cookie = `${name}=; ${expired}; path=/;`;
                document.cookie = `${name}=; ${expired}; path=/; domain=${hostname};`;
                document.cookie = `${name}=; ${expired}; path=/; domain=.${hostname};`;
            });

            console.log(`[PrivacyShield] ${cookies.length} cookie(s) cleared.`);
            return true;
        } catch (e) {
            console.error('[PrivacyShield] Cookie clear failed:', e);
            return false;
        }
    }

    async function clearIndexedDB() {
        try {
            if (!window.indexedDB || typeof indexedDB.databases !== 'function') return true;
            const dbs = await indexedDB.databases();
            if (!dbs.length) return true;

            const results = await Promise.all(dbs.map(db => new Promise(resolve => {
                const req = indexedDB.deleteDatabase(db.name);
                req.onsuccess = () => resolve(true);
                req.onerror = () => { console.warn(`[PrivacyShield] IndexedDB "${db.name}" delete error`); resolve(false); };
                req.onblocked = () => { console.warn(`[PrivacyShield] IndexedDB "${db.name}" blocked (other tab?)`); resolve(false); };
            })));

            console.log(`[PrivacyShield] ${dbs.length} IndexedDB database(s) cleared.`);
            return results.every(Boolean);
        } catch (e) {
            console.error('[PrivacyShield] IndexedDB clear failed:', e);
            return false;
        }
    }

    async function clearCacheAPI() {
        try {
            if (!window.caches) return true;
            const keys = await caches.keys();
            if (!keys.length) return true;
            await Promise.all(keys.map(k => caches.delete(k)));
            console.log(`[PrivacyShield] ${keys.length} Cache API store(s) cleared.`);
            return true;
        } catch (e) {
            console.error('[PrivacyShield] Cache API clear failed:', e);
            return false;
        }
    }

    async function unregisterServiceWorkers() {
        try {
            if (!navigator.serviceWorker) return true;
            const regs = await navigator.serviceWorker.getRegistrations();
            if (!regs.length) return true;
            await Promise.all(regs.map(r => r.unregister()));
            console.log(`[PrivacyShield] ${regs.length} Service Worker(s) unregistered.`);
            return true;
        } catch (e) {
            console.error('[PrivacyShield] Service Worker unregister failed:', e);
            return false;
        }
    }

    function clearWebSQL() {
        if (!window.openDatabase) return true;
        try {
            ['web_sql', 'site_', 'app_', 'local_', 'data_', 'db_'].forEach(pattern => {
                try {
                    const db = openDatabase(`temp_${pattern}`, '1.0', '', 1024 * 1024);
                    db.transaction(tx => tx.executeSql('DROP TABLE IF EXISTS main'));
                } catch (_) { /* Per-pattern errors are harmless */ }
            });
            console.log('[PrivacyShield] Web SQL cleanup attempted.');
        } catch (e) {
            console.warn('[PrivacyShield] Web SQL clear error:', e);
        }
        return true;
    }

    // =========================================================================
    // SECTION 7 — TOAST NOTIFICATIONS
    // =========================================================================

    function showToast(message, success = true, isWarning = false) {
        function _render() {
            document.querySelectorAll('.__ps_toast').forEach(el => el.remove());

            const toast = document.createElement('div');
            toast.className = '__ps_toast';

            const bg = success ? '#2e7d32' : (isWarning ? '#e65100' : '#c62828');

            Object.assign(toast.style, {
                position:      'fixed',
                top:           '18px',
                left:          '50%',
                transform:     'translateX(-50%) translateY(-12px)',
                padding:       '11px 22px',
                borderRadius:  '8px',
                background:    bg,
                color:         '#fff',
                fontSize:      '13px',
                fontFamily:    'system-ui, -apple-system, sans-serif',
                fontWeight:    '500',
                lineHeight:    '1.5',
                zIndex:        '2147483647',
                boxShadow:     '0 4px 18px rgba(0,0,0,0.35)',
                opacity:       '0',
                transition:    'opacity 0.25s ease, transform 0.25s ease',
                pointerEvents: 'none',
                maxWidth:      '88vw',
                textAlign:     'center',
                whiteSpace:    'pre-line',
            });
            toast.textContent = message;
            document.body.appendChild(toast);

            requestAnimationFrame(() => requestAnimationFrame(() => {
                toast.style.opacity   = '1';
                toast.style.transform = 'translateX(-50%) translateY(0)';
            }));

            setTimeout(() => {
                toast.style.opacity   = '0';
                toast.style.transform = 'translateX(-50%) translateY(-12px)';
                setTimeout(() => toast.remove(), 300);
            }, CONFIG.toastDuration);
        }

        if (document.body) {
            _render();
        } else {
            document.addEventListener('DOMContentLoaded', _render, { once: true });
        }
    }

    // =========================================================================
    // SECTION 8 — ACTION HANDLERS
    // =========================================================================

    async function actionClearAll() {
        if (!confirm(
            '⚠️  Clear ALL data for this site?\n\n' +
            'Includes: localStorage, sessionStorage, cookies,\n' +
            'IndexedDB, Cache API, Service Workers, Web SQL.\n\n' +
            'You may be logged out.  This cannot be undone.'
        )) return;

        try {
            const results = await Promise.all([
                clearLocalStorage(),
                clearSessionStorage(),
                clearCookies(),
                clearIndexedDB(),
                clearCacheAPI(),
                unregisterServiceWorkers(),
                clearWebSQL(),
            ]);

            const allOk = results.every(Boolean);
            _sessionStats.clearsPerformed++;
            refreshMenus();

            showToast(
                allOk
                    ? '✅  All site data cleared.'
                    : '⚠️  Partial clear — see console for details.',
                allOk, !allOk
            );

            if (allOk && confirm('Reload the page to complete cleanup?\n(Clears any server-set cookies too.)')) {
                location.reload();
            }
        } catch (e) {
            showToast('❌  Error during cleanup.', false);
            console.error('[PrivacyShield] clearAll error:', e);
        }
    }

    function actionClearBasic() {
        if (!confirm(
            'Clear localStorage and sessionStorage for this site?\n' +
            'Saved preferences and temporary data will be lost.'
        )) return;
        const ok = clearLocalStorage() && clearSessionStorage();
        _sessionStats.clearsPerformed++;
        refreshMenus();
        showToast(ok ? '✅  localStorage + sessionStorage cleared.' : '❌  Cleanup failed.', ok);
    }

    function actionClearCookies() {
        if (!confirm(
            'Clear all cookies for this site?\n' +
            'You may be logged out.'
        )) return;
        const ok = clearCookies();
        _sessionStats.clearsPerformed++;
        refreshMenus();
        showToast(ok ? '✅  Cookies cleared.' : '❌  Cookie cleanup failed.', ok);
    }

    async function actionClearDB() {
        if (!confirm(
            'Clear IndexedDB and Web SQL for this site?\n' +
            'Offline data and cached content will be removed.'
        )) return;
        const ok = (await clearIndexedDB()) && clearWebSQL();
        _sessionStats.clearsPerformed++;
        refreshMenus();
        showToast(
            ok ? '✅  IndexedDB + Web SQL cleared.' : '⚠️  Partial DB cleanup — see console.',
            ok, !ok
        );
    }

    async function actionClearCacheAndSW() {
        if (!confirm(
            'Clear Cache API stores and unregister Service Workers for this site?\n\n' +
            'This removes cached assets and any background tracking scripts.\n' +
            'The site will re-download resources on next load.'
        )) return;
        const ok = (await clearCacheAPI()) && (await unregisterServiceWorkers());
        _sessionStats.clearsPerformed++;
        refreshMenus();
        showToast(
            ok ? '✅  Cache + Service Workers cleared.' : '⚠️  Partial clear — see console.',
            ok, !ok
        );
    }

    function actionShowStats() {
        showToast(
            `📊  PrivacyShield — Session Stats\n` +
            `Tracking tokens stripped:  ${_sessionStats.tokensStripped}\n` +
            `Manual data clears done:   ${_sessionStats.clearsPerformed}`,
            true
        );
    }

    function actionOpenGitHub() {
        GM_openInTab('https://github.com/combined/privacy-shield', {
            active: true, insert: true, setParent: true,
        });
    }

    // =========================================================================
    // SECTION 9 — TAMPERMONKEY MENU
    // =========================================================================

    let _menuIds = [];

    function registerMenus() {
        _menuIds = [
            GM_registerMenuCommand('🗑️  Clear All Site Data...', actionClearAll),
            GM_registerMenuCommand('📦  Clear Storage (Local & Session)...', actionClearBasic),
            GM_registerMenuCommand('🍪  Clear Cookies...', actionClearCookies),
            GM_registerMenuCommand('🗄️  Clear Databases (IndexedDB & Web SQL)...', actionClearDB),
            GM_registerMenuCommand('⚡  Clear Caches & Service Workers...', actionClearCacheAndSW),
            GM_registerMenuCommand(`📊  Session Stats (stripped: ${_sessionStats.tokensStripped})`, actionShowStats),
            GM_registerMenuCommand('🔗  PrivacyShield on GitHub', actionOpenGitHub),
        ];
    }

    function refreshMenus() {
        _menuIds.forEach(id => { try { GM_unregisterMenuCommand(id); } catch (_) {} });
        registerMenus();
    }

    setInterval(refreshMenus, 10000);

    registerMenus();

    console.log('[PrivacyShield v2.1.0] Loaded — token stripper active, referrer suppressed, data cleaner ready via Tampermonkey menu.');

})();
