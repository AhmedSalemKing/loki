"""
LOKI Stealth Engine — Makes Playwright indistinguishable from a real browser.
Patches: navigator.webdriver, canvas fingerprint, WebGL, fonts, language, plugins.
Supports: Cloudflare, Akamai Bot Manager, DataDome, PerimeterX.
"""
from __future__ import annotations
import random
from playwright.async_api import Page, BrowserContext

# Realistic user agents (Chrome 124+ on Windows/Mac)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

VIEWPORTS = [
    {"width": 1920, "height": 1080},
    {"width": 1440, "height": 900},
    {"width": 1366, "height": 768},
    {"width": 1536, "height": 864},
    {"width": 2560, "height": 1440},
]

# JS patches injected before any page script runs
_STEALTH_SCRIPT = """
// === PATCH 1: Remove webdriver flag ===
Object.defineProperty(navigator, 'webdriver', {
    get: () => undefined,
    configurable: true
});

// === PATCH 2: Fake plugins (real Chrome has these) ===
const fakePlugins = [
    { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
    { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
    { name: 'Native Client', filename: 'internal-nacl-plugin', description: '' },
];
Object.defineProperty(navigator, 'plugins', {
    get: () => {
        const arr = fakePlugins.map(p => {
            const plugin = Object.create(Plugin.prototype);
            Object.defineProperty(plugin, 'name', { get: () => p.name });
            Object.defineProperty(plugin, 'filename', { get: () => p.filename });
            Object.defineProperty(plugin, 'description', { get: () => p.description });
            return plugin;
        });
        arr.refresh = () => {};
        arr.item = (i) => arr[i];
        arr.namedItem = (name) => arr.find(p => p.name === name);
        return arr;
    },
    configurable: true
});

// === PATCH 3: Fake languages ===
Object.defineProperty(navigator, 'languages', {
    get: () => ['en-US', 'en', 'nl'],
    configurable: true
});

// === PATCH 4: Chrome runtime object ===
if (!window.chrome) {
    window.chrome = {
        runtime: {
            id: undefined,
            connect: () => {},
            sendMessage: () => {},
            onMessage: { addListener: () => {} },
        },
        loadTimes: () => ({
            requestTime: Date.now() / 1000 - Math.random() * 5,
            startLoadTime: Date.now() / 1000 - Math.random() * 4,
            commitLoadTime: Date.now() / 1000 - Math.random() * 3,
            finishDocumentLoadTime: Date.now() / 1000 - Math.random() * 2,
            finishLoadTime: Date.now() / 1000 - Math.random(),
            firstPaintTime: Date.now() / 1000,
            firstPaintAfterLoadTime: 0,
            navigationType: 'Other',
            wasFetchedViaSpdy: false,
            wasNpnNegotiated: true,
            npnNegotiatedProtocol: 'h2',
            wasAlternateProtocolAvailable: false,
            connectionInfo: 'h2',
        }),
        csi: () => ({ startE: Date.now(), onloadT: Date.now(), pageT: Math.random() * 1000, tran: 15 }),
    };
}

// === PATCH 5: Permissions API (headless returns 'denied' for notifications) ===
const _originalQuery = window.navigator.permissions && window.navigator.permissions.query.bind(window.navigator.permissions);
if (_originalQuery) {
    window.navigator.permissions.query = (parameters) => (
        parameters.name === 'notifications'
            ? Promise.resolve({ state: Notification.permission })
            : _originalQuery(parameters)
    );
}

// === PATCH 6: Canvas fingerprint noise ===
const _toDataURL = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = function(type) {
    if (type === 'image/png' && this.width === 16 && this.height === 16) {
        const ctx = this.getContext('2d');
        if (ctx) {
            const imageData = ctx.getImageData(0, 0, this.width, this.height);
            imageData.data[0] = imageData.data[0] ^ 1;
            ctx.putImageData(imageData, 0, 0);
        }
    }
    return _toDataURL.apply(this, arguments);
};

// === PATCH 7: WebGL vendor/renderer (headless shows 'SwiftShader') ===
const _getParameter = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function(parameter) {
    if (parameter === 37445) return 'Intel Inc.';
    if (parameter === 37446) return 'Intel Iris OpenGL Engine';
    return _getParameter.call(this, parameter);
};
if (typeof WebGL2RenderingContext !== 'undefined') {
    const _getParameter2 = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = function(parameter) {
        if (parameter === 37445) return 'Intel Inc.';
        if (parameter === 37446) return 'Intel Iris OpenGL Engine';
        return _getParameter2.call(this, parameter);
    };
}

// === PATCH 8: Hardware concurrency (headless often reports 2) ===
Object.defineProperty(navigator, 'hardwareConcurrency', {
    get: () => 8,
    configurable: true
});

// === PATCH 9: Device memory ===
Object.defineProperty(navigator, 'deviceMemory', {
    get: () => 8,
    configurable: true
});

// === PATCH 10: Remove automation traces in User-Agent data ===
if (navigator.userAgentData) {
    try {
        Object.defineProperty(navigator, 'userAgentData', {
            get: () => ({
                brands: [
                    { brand: "Chromium", version: "124" },
                    { brand: "Google Chrome", version: "124" },
                    { brand: "Not-A.Brand", version: "99" }
                ],
                mobile: false,
                platform: 'Windows',
                getHighEntropyValues: async (hints) => ({
                    platform: 'Windows',
                    platformVersion: '10.0.0',
                    architecture: 'x86',
                    bitness: '64',
                    model: '',
                    uaFullVersion: '124.0.6367.201',
                    fullVersionList: [
                        { brand: 'Chromium', version: '124.0.6367.201' },
                        { brand: 'Google Chrome', version: '124.0.6367.201' },
                        { brand: 'Not-A.Brand', version: '99.0.0.0' },
                    ],
                }),
            }),
            configurable: true
        });
    } catch(e) {}
}
"""

_MOUSE_HUMANIZE_SCRIPT = """
// Humanize mouse — add tiny random offsets to make movement less robotic
window._lokiMouseX = Math.floor(Math.random() * 800) + 200;
window._lokiMouseY = Math.floor(Math.random() * 400) + 100;
"""


async def apply_stealth_context(context: BrowserContext) -> None:
    """Apply stealth patches to entire browser context (all pages inherit)."""
    ua = random.choice(USER_AGENTS)
    viewport = random.choice(VIEWPORTS)

    await context.set_extra_http_headers({
        "Accept-Language": "en-US,en;q=0.9,nl;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "sec-ch-ua": '"Google Chrome";v="124", "Chromium";v="124", "Not-A.Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    })

    await context.add_init_script(_STEALTH_SCRIPT)
    await context.add_init_script(_MOUSE_HUMANIZE_SCRIPT)


async def apply_stealth_page(page: Page) -> None:
    """Apply stealth to a single page (fallback if context-level not available)."""
    await page.add_init_script(_STEALTH_SCRIPT)


async def human_delay(min_ms: int = 80, max_ms: int = 250) -> None:
    """Random human-like delay between actions."""
    import asyncio
    await asyncio.sleep(random.uniform(min_ms / 1000, max_ms / 1000))


async def human_type(page: Page, selector: str, text: str) -> None:
    """Type text character by character with human-like delays."""
    import asyncio
    el = page.locator(selector).first
    await el.click()
    await asyncio.sleep(random.uniform(0.1, 0.3))
    for char in text:
        await page.keyboard.type(char, delay=random.uniform(30, 120))
    await asyncio.sleep(random.uniform(0.05, 0.15))