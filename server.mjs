#!/usr/bin/env node
/**
 * TikTok Signature Server
 *
 * Generates valid X-Bogus and X-Gnarly signatures for TikTok API requests.
 * Uses a persistent browser session with local SDK injection for reliable signature generation.
 *
 * Endpoints:
 * - POST /signature - Generate signed URL (body: { "url": "..." }) - RECOMMENDED for scalability
 * - POST /fetch     - Fetch through browser (slower, but 100% reliable fallback)
 * - GET  /health    - Health check
 * - GET  /restart   - Restart browser session
 *
 * Environment Variables:
 * - PORT          - Server port (default: 8080)
 * - PROXY_ENABLED - Enable proxy (default: false)
 * - PROXY_HOST    - Proxy host:port (e.g., "proxy.example.com:8080")
 * - PROXY_USER    - Proxy username
 * - PROXY_PASS    - Proxy password
 */

import http from "http";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import puppeteer from "puppeteer-extra";
import StealthPlugin from "puppeteer-extra-plugin-stealth";
import { encode as encodeXGnarly } from "./xgnarly.mjs";

// Use stealth plugin with default evasions
puppeteer.use(StealthPlugin());

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8080;

// Custom user data directory to avoid filling /tmp
const USER_DATA_DIR = path.join(__dirname, ".chrome-profile");

// User agent - Safari on macOS
const DEFAULT_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15";

// Current active user agent (can be overridden per-request)
let currentUserAgent = DEFAULT_UA;

// Proxy configuration from environment
const PROXY_ENABLED =
  process.env.PROXY_ENABLED === "true" && process.env.PROXY_HOST;
const PROXY_HOST = process.env.PROXY_HOST || "";
const PROXY_USER = process.env.PROXY_USER || "";
const PROXY_PASS = process.env.PROXY_PASS || "";

// Local SDK path - the SDK is used to generate valid signatures
const SDK_PATH = path.join(__dirname, "javascript", "webmssdk_5.1.3.js");
let localSdkContent = null;

// Versioned SDK files served in place of the CDN copies.
const SDK_368_PATH = path.join(
  __dirname,
  "javascript",
  "webmssdk_1.0.0.368.js",
);
const SDK_485_PATH = path.join(
  __dirname,
  "javascript",
  "webmssdk_2.0.0.485.js",
);
let sdk368 = null;
let sdk485 = null;
try {
  if (fs.existsSync(SDK_368_PATH)) {
    sdk368 = fs.readFileSync(SDK_368_PATH, "utf-8");
    console.log("[Server] Loaded:", SDK_368_PATH);
  }
  if (fs.existsSync(SDK_485_PATH)) {
    sdk485 = fs.readFileSync(SDK_485_PATH, "utf-8");
    console.log("[Server] Loaded:", SDK_485_PATH);
  }
} catch (e) {
  console.log("[Server] SDK load error:", e.message);
}

// Try to load local SDK
try {
  if (fs.existsSync(SDK_PATH)) {
    localSdkContent = fs.readFileSync(SDK_PATH, "utf-8");
    console.log("[Server] Local SDK loaded:", SDK_PATH);
  }
} catch (e) {
  console.log("[Server] Local SDK not found:", e.message);
}

// Browser state
let browser = null;
let page = null;
let cookies = null;
let isInitializing = false;
let isReady = false;
let generationCount = 0;
let initMethod = null;
let lastInitTime = null;

// Cache of page-emitted signed URLs, keyed by pathname.
const signedUrlCache = new Map();
const SIGNED_CACHE_MAX_AGE_MS = 60_000;

// Auto-refresh configuration to avoid blocks
const MAX_GENERATIONS_BEFORE_REFRESH = 500; // Restart browser after this many signatures
const MAX_SESSION_AGE_MS = 30 * 60 * 1000; // Restart browser after 30 minutes

// Request queue for sequential processing (prevents concurrent access to browser page)
const requestQueue = [];
let isProcessingQueue = false;

/**
 * Add a signature request to the queue and process sequentially
 */
function queueSignatureRequest(signFn) {
  return new Promise((resolve, reject) => {
    const queuePosition = requestQueue.length + 1;
    if (queuePosition > 1) {
      console.log(`[Queue] Request queued at position ${queuePosition}`);
    }
    requestQueue.push({ signFn, resolve, reject });
    processQueue();
  });
}

/**
 * Process the queue sequentially
 */
async function processQueue() {
  if (isProcessingQueue || requestQueue.length === 0) {
    return;
  }

  isProcessingQueue = true;

  while (requestQueue.length > 0) {
    const { signFn, resolve, reject } = requestQueue.shift();
    const remaining = requestQueue.length;
    if (remaining > 0) {
      console.log(
        `[Queue] Processing request, ${remaining} remaining in queue`,
      );
    }
    try {
      const result = await signFn();
      resolve(result);
    } catch (e) {
      console.error(`[Queue] Request failed: ${e.message}`);
      reject(e);
    }
  }

  isProcessingQueue = false;
}

/**
 * Initialize browser with local SDK injection
 */
async function initBrowser() {
  if (isInitializing) {
    // Wait for initialization to complete
    while (isInitializing) {
      await new Promise((r) => setTimeout(r, 100));
    }
    return;
  }

  if (isReady && browser && page) {
    return;
  }

  isInitializing = true;
  console.log("[Server] Initializing browser...");

  try {
    // Determine Chrome executable path
    const getChromePath = () => {
      // Check for Docker/env override first
      if (process.env.PUPPETEER_EXECUTABLE_PATH) {
        return process.env.PUPPETEER_EXECUTABLE_PATH;
      }
      // macOS
      if (process.platform === "darwin") {
        return "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
      }
      // Linux - try common paths
      if (process.platform === "linux") {
        const paths = [
          "/usr/bin/chromium",
          "/usr/bin/chromium-browser",
          "/usr/bin/google-chrome",
          "/usr/bin/google-chrome-stable",
        ];
        for (const p of paths) {
          try {
            fs.accessSync(p);
            return p;
          } catch {}
        }
      }
      return undefined; // Let Puppeteer find it
    };

    // Build browser args
    const browserArgs = [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-blink-features=AutomationControlled",
      "--disable-gpu",
      "--window-size=1920,1080",
    ];

    // Add proxy if enabled
    if (PROXY_ENABLED) {
      browserArgs.push(`--proxy-server=http://${PROXY_HOST}`);
      console.log(`[Server] Proxy enabled: ${PROXY_HOST}`);
    } else {
      console.log("[Server] Proxy disabled - direct connection");
    }

    // Ensure user data directory exists
    if (!fs.existsSync(USER_DATA_DIR)) {
      fs.mkdirSync(USER_DATA_DIR, { recursive: true });
    }

    browser = await puppeteer.launch({
      headless: "new",
      executablePath: getChromePath(),
      args: browserArgs,
      userDataDir: USER_DATA_DIR,
      ignoreDefaultArgs: ["--enable-automation"],
    });

    page = await browser.newPage();

    // Permanent passive listener: every signed request the page emits gets
    // cached by its pathname. /signature reads this cache and returns the
    // freshest URL without navigating.
    page.on("request", (request) => {
      try {
        const u = request.url();
        if (!u.includes("X-Gnarly=")) return;
        const parsed = new URL(u);
        signedUrlCache.set(parsed.pathname, {
          url: u,
          capturedAt: Date.now(),
          referer: request.headers().referer || "",
        });
      } catch (e) {}
    });

    // Authenticate with proxy if enabled
    if (PROXY_ENABLED && PROXY_USER && PROXY_PASS) {
      await page.authenticate({
        username: PROXY_USER,
        password: PROXY_PASS,
      });
    }

    await page.setUserAgent(DEFAULT_UA);
    await page.setViewport({ width: 1920, height: 1080 });

    // Apply platform override to match Safari on macOS
    await page.evaluateOnNewDocument(() => {
      Object.defineProperty(navigator, "platform", {
        get: () => "MacIntel",
        configurable: true,
      });
    });

    await page.evaluateOnNewDocument(() => {
      if (typeof window.process === "undefined") {
        window.process = {
          env: { NODE_ENV: "production" },
          browser: true,
          version: "",
          versions: {},
        };
      }
    });

    // Initialize with local SDK
    await initWithLocalSdk();
    lastInitTime = new Date().toISOString();
    console.log(`[Server] Browser ready (init method: ${initMethod})`);
    isReady = true;
  } catch (e) {
    console.error("[Server] Init error:", e.message);
    await closeBrowser();
    throw e;
  } finally {
    isInitializing = false;
  }
}

/**
 * Detect TikTok's "Something went wrong" interstitial and click its Refresh
 * button. Returns true if the error was detected and handled, false otherwise.
 * Tries up to 2 retries since the second load occasionally errors too.
 */
async function dismissTikTokErrorIfPresent(maxAttempts = 2) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const state = await page.evaluate(() => {
      const text = document.body ? document.body.innerText || "" : "";
      const hasError = /Something went wrong/i.test(text);
      const refreshBtn = Array.from(document.querySelectorAll("button")).find(
        (b) => /^\s*Refresh\s*$/i.test(b.textContent || ""),
      );
      return { hasError, hasRefreshBtn: !!refreshBtn };
    });
    if (!state.hasError) {
      return attempt === 1 ? false : true;
    }
    console.log(
      `[Server] Detected "Something went wrong" interstitial (attempt ${attempt}/${maxAttempts}), clicking Refresh...`,
    );
    await page.evaluate(() => {
      const btn = Array.from(document.querySelectorAll("button")).find((b) =>
        /^\s*Refresh\s*$/i.test(b.textContent || ""),
      );
      if (btn) btn.click();
    });
    // Wait for the bundle to re-initialise after the click
    try {
      await page.waitForNavigation({
        waitUntil: "domcontentloaded",
        timeout: 30000,
      });
    } catch (e) {
      // Some refreshes don't trigger a full navigation; just wait
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
  return true;
}

/**
 * Initialize with TikTok page context and LOCAL SDK
 * Injects local SDK BEFORE page loads using evaluateOnNewDocument
 */
async function initWithLocalSdk() {
  if (!localSdkContent) {
    throw new Error(
      "Local SDK not available - ensure webmssdk_5.1.3.js exists in javascript/ folder",
    );
  }

  console.log("[Server] Injecting local SDK before navigation...");

  // Inject SDK before any page scripts run
  await page.evaluateOnNewDocument((sdkCode) => {
    try {
      eval(sdkCode);
      console.log("[SDK] Injected via evaluateOnNewDocument");
    } catch (e) {
      console.error("[SDK] Injection error:", e.message);
    }
  }, localSdkContent);

  // Set up request interception to block TikTok's SDK (prevent conflicts)
  console.log("[Server] Setting up request interception...");
  await page.setRequestInterception(true);

  const requestHandler = async (request) => {
    const url = request.url();
    const resourceType = request.resourceType();

    if (url.includes("/webmssdk/")) {
      let body = null;
      if (url.includes("2.0.0.485") && sdk485) body = sdk485;
      else if (url.includes("1.0.0.368") && sdk368) body = sdk368;
      else if (sdk485) body = sdk485;
      if (body) {
        try {
          await request.respond({
            status: 200,
            contentType: "application/javascript; charset=utf-8",
            body,
          });
        } catch (e) {
          await request.abort();
        }
        return;
      }
    }

    // Block other security/telemetry SDK files (we don't want them interfering)
    if (
      url.includes("/webmssdk/") ||
      url.includes("slardar") ||
      url.includes("acrawler")
    ) {
      await request.abort();
      return;
    }

    // Block heavy resources to speed up loading
    if (["image", "media", "font"].includes(resourceType)) {
      await request.abort();
      return;
    }

    await request.continue();
  };

  page.on("request", requestHandler);

  console.log("[Server] Navigating to TikTok...");
  await page.goto("https://www.tiktok.com/@zara", {
    waitUntil: "domcontentloaded",
    timeout: 60000,
  });

  // Wait for page to settle and SDK to initialize
  console.log("[Server] Waiting for SDK...");
  await new Promise((r) => setTimeout(r, 3000));

  // Check SDK status
  const sdkStatus = await page.evaluate(() => {
    const hasAcrawler = !!window.byted_acrawler;
    const hasFrontierSign =
      hasAcrawler && typeof window.byted_acrawler.frontierSign === "function";
    const keys = window.byted_acrawler
      ? Object.keys(window.byted_acrawler).slice(0, 10)
      : [];
    return { hasAcrawler, hasFrontierSign, keys };
  });

  console.log("[Server] SDK status:", JSON.stringify(sdkStatus));

  if (!sdkStatus.hasFrontierSign) {
    throw new Error(
      `Local SDK failed to initialize: ${JSON.stringify(sdkStatus)}`,
    );
  }

  initMethod = "local-sdk";
  console.log("[Server] Local SDK initialized successfully");

  // Interception remains active across navigations.

  // Warm up the SDK
  console.log("[Server] Warming up SDK...");
  await page.evaluate(() => window.scrollBy(0, 500));
  await new Promise((r) => setTimeout(r, 2000));

  // Always reload after the initial load. First load is unreliable — sometimes
  // a blank/white page, sometimes the "Something went wrong" interstitial. The
  // reload primes the second pass with the cookies/msToken accumulated on the
  // first pass, after which the page bundle reliably emits signed requests.
  console.log("[Server] Reloading page to stabilize session...");
  try {
    await page.reload({ waitUntil: "domcontentloaded", timeout: 60000 });
  } catch (e) {
    console.log("[Server] Reload warning:", e.message);
  }
  await new Promise((r) => setTimeout(r, 3000));

  // If the second pass still shows the "Something went wrong" interstitial,
  // click its in-page Refresh button to retry once more.
  await dismissTikTokErrorIfPresent();

  // Extract cookies for use in requests
  cookies = await page.cookies();
  console.log(`[Server] Captured ${cookies.length} cookies`);
}

async function closeBrowser() {
  isReady = false;
  cookies = null;
  generationCount = 0;
  initMethod = null;
  lastInitTime = null;

  if (browser) {
    try {
      await browser.close();
    } catch (e) {
      console.error("[Server] Error closing browser:", e.message);
    }
    browser = null;
    page = null;
  }

  // Clean up user data directory to prevent disk space accumulation
  try {
    if (fs.existsSync(USER_DATA_DIR)) {
      fs.rmSync(USER_DATA_DIR, { recursive: true, force: true });
      console.log("[Server] Cleaned up browser profile directory");
    }
  } catch (e) {
    console.error("[Server] Error cleaning up profile:", e.message);
  }

  console.log("[Server] Browser closed, all state reset");
}

/**
 * Check if the browser session should be refreshed based on age or generation count
 */
function shouldRefreshSession() {
  if (!lastInitTime) return false;

  const sessionAge = Date.now() - new Date(lastInitTime).getTime();

  if (generationCount >= MAX_GENERATIONS_BEFORE_REFRESH) {
    console.log(
      `[Server] Session refresh needed: ${generationCount} generations reached`,
    );
    return true;
  }

  if (sessionAge >= MAX_SESSION_AGE_MS) {
    console.log(
      `[Server] Session refresh needed: ${Math.round(sessionAge / 60000)} minutes elapsed`,
    );
    return true;
  }

  return false;
}

/**
 * Check if the page is still valid and ready
 */
async function ensurePageReady() {
  try {
    if (!browser || !page) {
      throw new Error("Browser or page not initialized");
    }

    // Check if session should be refreshed to avoid blocks
    if (shouldRefreshSession()) {
      console.log("[Server] Proactive session refresh...");
      await closeBrowser();
      await initBrowser();
      return true;
    }

    await page.mainFrame();
    return true;
  } catch (e) {
    console.log("[Server] Page invalid, reinitializing...", e.message);
    isReady = false;
    await closeBrowser();
    await initBrowser();
    return true;
  }
}

/**
 * Generate signed URL for any TikTok URL
 * Triggers fetch, SDK signs it, we capture and abort
 * @param {string} targetUrl - The URL to sign
 * @param {string|null} userAgent - Optional custom user agent to return in response
 */
async function generateSignedUrl(
  targetUrl,
  userAgent = null,
  navigateTo = null,
) {
  return queueSignatureRequest(() =>
    _generateSignedUrlInternal(targetUrl, userAgent, navigateTo),
  );
}

/**
 * Internal implementation - must be called through queue
 * @param {string} targetUrl - The URL to sign
 * @param {string|null} userAgent - Optional UA to return in response
 * @param {string|null} navigateTo - Optional TikTok page URL; when given,
 * the response uses a page-intercept path instead of the default fast path.
 */
async function _generateSignedUrlInternal(
  targetUrl,
  userAgent = null,
  navigateTo = null,
) {
  await initBrowser();
  await ensurePageReady();

  // Parse target URL - remove existing signatures and normalize fingerprint params
  const urlObj = new URL(targetUrl);
  urlObj.searchParams.delete("X-Bogus");
  urlObj.searchParams.delete("X-Gnarly");
  urlObj.searchParams.delete("msToken");
  normalizeUrlFingerprint(urlObj);
  const fetchUrl = urlObj.toString();

  if (navigateTo) {
    console.log(`[Server] Sign via page intercept: navigateTo=${navigateTo}`);
    return _signViaPageIntercept(fetchUrl, navigateTo, userAgent);
  }

  console.log(`[Server] Signing URL: ${fetchUrl.substring(0, 100)}...`);
  return _signDirectly(fetchUrl, userAgent);
}

async function _signViaPageIntercept(targetUrl, navigateTo, userAgent = null) {
  const targetPath = new URL(targetUrl).pathname;
  const callStart = Date.now();

  // Always navigate per call — that's the only reliable way to get a fresh
  // signed URL that TikTok will accept on external fetch. Cache-reuse and
  // scroll-trigger were both tried and produced unfetchable URLs.
  await page.goto(navigateTo, {
    waitUntil: "domcontentloaded",
    timeout: 60000,
  });
  await dismissTikTokErrorIfPresent();

  // Wait for the permanent listener to capture a matching signed URL emitted
  // after this call started (rules out a stale entry left from a prior nav).
  // Residential proxies can be slow — give it 15s.
  const WAIT_MS = 15000;
  while (Date.now() - callStart < WAIT_MS) {
    const c = signedUrlCache.get(targetPath);
    if (c && c.capturedAt >= callStart) {
      cookies = await page.cookies();
      generationCount++;
      return parseResult(c.url, userAgent);
    }
    await new Promise((r) => setTimeout(r, 50));
  }

  throw new Error(
    `No fresh ${targetPath} request emitted by ${navigateTo} within ${WAIT_MS / 1000}s`,
  );
}

async function _signDirectly(fetchUrl, userAgent = null) {
  const out = await page.evaluate((url) => {
    if (typeof window.__sdkN === "undefined") {
      return { error: "SDK not initialized" };
    }
    const sdkN = window.__sdkN;
    let table = null;
    if (sdkN.u && sdkN.u[995] && sdkN.u[995].v) table = sdkN.u;
    else if (sdkN.B && sdkN.B.o && sdkN.B.o[995] && sdkN.B.o[995].v)
      table = sdkN.B.o;
    else if (sdkN.o && sdkN.o[995] && sdkN.o[995].v) table = sdkN.o;
    if (!table) return { error: "SDK not ready" };
    const u995 = table[995] && table[995].v;
    if (typeof u995 !== "function") {
      return { error: "SDK not ready" };
    }

    const u = new URL(url);
    const msTokenMatches = document.cookie.match(/msToken=([^;]+)/g) || [];
    const msToken = msTokenMatches.length
      ? msTokenMatches[msTokenMatches.length - 1].split("=", 2)[1]
      : "";
    u.searchParams.delete("X-Bogus");
    u.searchParams.delete("X-Gnarly");
    u.searchParams.set("msToken", msToken);
    const queryString = u.search.slice(1);

    if (typeof window.__sigCallCount !== "number") window.__sigCallCount = 100;
    window.__sigCallCount += 1;
    const baseN = window.__sigCallCount;
    let counterObj = {
      totalXHRRequests: Math.floor(baseN * 0.6),
      totalFetchRequests: Math.floor(baseN * 0.4) + 3,
      interceptedXHRRequests: Math.floor(baseN * 0.1),
      interceptedFetchRequests: Math.floor(baseN * 0.05) + 1,
    };
    try {
      const cap3 = window.__cap3 || [];
      const lastNat = [...cap3]
        .reverse()
        .find((c) => c.fn === "gnarly_x" && c.args && c.args[3] && c.args[3].v);
      if (lastNat && lastNat.args[3].v) {
        const v = lastNat.args[3].v;
        const fromCap = {
          totalXHRRequests: (v.totalXHRRequests && v.totalXHRRequests.v) || 0,
          totalFetchRequests:
            (v.totalFetchRequests && v.totalFetchRequests.v) || 0,
          interceptedXHRRequests:
            (v.interceptedXHRRequests && v.interceptedXHRRequests.v) || 0,
          interceptedFetchRequests:
            (v.interceptedFetchRequests && v.interceptedFetchRequests.v) || 0,
        };
        if (fromCap.totalXHRRequests + fromCap.totalFetchRequests > 0) {
          counterObj = fromCap;
        }
      }
    } catch (e) {}

    const acrawlerInst =
      window.byted_acrawler && typeof window.byted_acrawler === "object"
        ? window.byted_acrawler
        : null;
    try {
      const xb = u995.call(acrawlerInst, queryString, "");
      return {
        urlBase: u.toString(),
        queryString,
        xBogus: xb,
        msTokenUsed: msToken,
        userAgent: navigator.userAgent,
        cookies: document.cookie,
        counters: counterObj,
      };
    } catch (e) {
      return { error: e.message, stack: e.stack };
    }
  }, fetchUrl);

  if (out.error) {
    throw new Error("Sign failed: " + out.error);
  }

  const xg = encodeXGnarly(out.queryString, "", out.userAgent, out.counters, {
    ubcode: 4,
    sdkVersion: "1.0.0.368",
  });

  const u = new URL(out.urlBase);
  u.searchParams.set("X-Bogus", out.xBogus);
  u.searchParams.set("X-Gnarly", xg);

  cookies = await page.cookies();
  generationCount++;
  return parseResult(u.toString(), userAgent);
}

/**
 * Normalize browser fingerprint query parameters to match the browser environment.
 * TikTok's X-Bogus signature encodes the browser's actual fingerprint, so the URL
 * params must be consistent with the browser environment or TikTok returns
 * "url doesn't match".
 * Only overwrites params that are already present in the URL.
 * @param {URL} urlObj - The URL object to normalize in place
 */
function normalizeUrlFingerprint(urlObj) {
  const params = urlObj.searchParams;

  // Map of fingerprint param -> correct value for our browser environment
  const fingerprint = {
    browser_platform: "MacIntel", // matches navigator.platform override
    os: "mac", // matches Safari macOS UA
    screen_width: "1920", // matches viewport
    screen_height: "1080", // matches viewport
  };

  let normalized = false;
  for (const [key, correctValue] of Object.entries(fingerprint)) {
    if (params.has(key) && params.get(key) !== correctValue) {
      console.log(
        `[Server] Normalizing ${key}: "${params.get(key)}" -> "${correctValue}"`,
      );
      params.set(key, correctValue);
      normalized = true;
    }
  }

  if (normalized) {
    console.log(
      "[Server] URL fingerprint params normalized to match browser environment",
    );
  }
}

/**
 * Sign URL using fetch interception
 * SDK intercepts fetch and adds signature params (X-Bogus, X-Gnarly)
 * @param {string} fetchUrl - The URL to sign
 * @param {string|null} userAgent - Optional custom user agent to return in response
 */
async function _signWithFetchInterception(fetchUrl, userAgent = null) {
  return new Promise(async (resolve, reject) => {
    let signedUrl = null;
    let timeout = null;
    let resolved = false;
    let cleanedUp = false;

    async function cleanup() {
      if (cleanedUp) return;
      cleanedUp = true;
      try {
        page.off("request", requestHandler);
        await page.setRequestInterception(false);
      } catch (e) {
        // Ignore cleanup errors
      }
    }

    const requestHandler = async (request) => {
      if (resolved) {
        try {
          if (!request.isInterceptResolutionHandled()) {
            await request.abort("aborted");
          }
        } catch (e) {}
        return;
      }

      const url = request.url();

      // Capture any signed request (contains X-Bogus)
      if (url.includes("X-Bogus") && !signedUrl) {
        signedUrl = url;

        if (!resolved) {
          resolved = true;
          clearTimeout(timeout);
          await cleanup();
          generationCount++;
          resolve(parseResult(signedUrl, userAgent));
        }
      }

      // Abort request
      try {
        if (!request.isInterceptResolutionHandled()) {
          await request.abort("aborted");
        }
      } catch (e) {}
    };

    try {
      await page.setRequestInterception(true);
    } catch (e) {
      reject(new Error("Failed to enable request interception: " + e.message));
      return;
    }

    page.on("request", requestHandler);

    // Timeout fallback
    timeout = setTimeout(async () => {
      if (!resolved) {
        resolved = true;
        await cleanup();
        if (signedUrl) {
          generationCount++;
          resolve(parseResult(signedUrl, userAgent));
        } else {
          reject(new Error("Timeout waiting for signed URL"));
        }
      }
    }, 5000);

    // Trigger fetch - SDK will sign it
    try {
      page
        .evaluate((url) => {
          fetch(url, {
            method: "GET",
            credentials: "include",
            headers: { Accept: "*/*" },
          }).catch(() => {});
        }, fetchUrl)
        .catch((e) => {
          if (!resolved) {
            console.error("[Server] page.evaluate failed:", e.message);
          }
        });
    } catch (e) {
      if (!resolved) {
        resolved = true;
        clearTimeout(timeout);
        await cleanup();
        reject(new Error("page.evaluate failed: " + e.message));
      }
    }
  });
}

function parseResult(url, userAgent = null) {
  const urlObj = new URL(url);
  const cookieString = cookies
    ? cookies.map((c) => `${c.name}=${c.value}`).join("; ")
    : "";
  return {
    signedUrl: url,
    xBogus: urlObj.searchParams.get("X-Bogus"),
    xGnarly: urlObj.searchParams.get("X-Gnarly"),
    secUid: urlObj.searchParams.get("secUid"),
    cursor: urlObj.searchParams.get("cursor"),
    deviceId: urlObj.searchParams.get("device_id"),
    userAgent: userAgent || currentUserAgent,
    cookies: cookieString,
  };
}

/**
 * HTTP Request Handler
 */
async function handleRequest(req, res) {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Content-Type", "application/json");

  if (req.method === "OPTIONS") {
    res.writeHead(200);
    res.end();
    return;
  }

  try {
    // Health check — trigger init browser để giữ server warm khi bị ping
    if (url.pathname === "/health") {
      // Nếu browser chưa ready, khởi động ngầm (không await để trả response ngay)
      if (!isReady && !isInitializing) {
        console.log("[Health] Browser chưa sẵn sàng, đang khởi động ngầm...");
        initBrowser().catch(e => console.error("[Health] Init error:", e.message));
      }
      const sessionAge = lastInitTime
        ? Date.now() - new Date(lastInitTime).getTime()
        : 0;
      res.writeHead(200);
      res.end(
        JSON.stringify({
          status: "ok",
          ready: isReady,
          initializing: isInitializing,
          initMethod: initMethod,
          lastInitTime: lastInitTime,
          sessionAgeMinutes: Math.round(sessionAge / 60000),
          generationCount: generationCount,
          maxGenerationsBeforeRefresh: MAX_GENERATIONS_BEFORE_REFRESH,
          maxSessionAgeMinutes: MAX_SESSION_AGE_MS / 60000,
          queueLength: requestQueue.length,
          isProcessing: isProcessingQueue,
          localSdkAvailable: !!localSdkContent,
          proxyEnabled: PROXY_ENABLED,
          userAgent: currentUserAgent,
        }),
      );
      return;
    }

    // Fetch endpoint - makes request through browser (slower, but 100% reliable fallback)
    // Use /signature + external requests for better scalability
    if (url.pathname === "/fetch" && req.method === "POST") {
      let body = "";
      for await (const chunk of req) {
        body += chunk;
      }

      let targetUrl = null;
      let cookieHeader = null;
      try {
        const json = JSON.parse(body);
        targetUrl = json.url;
        cookieHeader = json.cookie || null;
      } catch (e) {
        try {
          new URL(body.trim());
          targetUrl = body.trim();
        } catch (e2) {}
      }

      if (!targetUrl) {
        res.writeHead(400);
        res.end(
          JSON.stringify({ status: "error", message: "URL is required" }),
        );
        return;
      }

      await initBrowser();
      await ensurePageReady();

      console.log(
        "[Server] Fetching through browser:",
        targetUrl.substring(0, 80) + "...",
      );

      // Nếu request truyền lên custom cookie, bóc tách và set vào page
      if (cookieHeader) {
        const cookieList = [];
        for (const part of cookieHeader.split(";")) {
          const p = part.trim();
          const idx = p.indexOf("=");
          if (idx === -1) continue;
          cookieList.push({ name: p.slice(0, idx).trim(), value: p.slice(idx+1).trim(), domain: ".tiktok.com", path: "/" });
        }
        try { await page.setCookie(...cookieList); } catch(e) {}
      }

      const fetchResult = await page.evaluate(async (url) => {
        try {
          const response = await fetch(url, {
            method: "POST",
            credentials: "include",
            headers: { "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded", "Content-Length": "0" },
          });
          const text = await response.text();
          return {
            status: response.status,
            bodyLength: text.length,
            data: text ? JSON.parse(text) : null,
          };
        } catch (e) {
          return { error: e.message };
        }
      }, targetUrl);

      console.log(
        "[Server] Fetch result:",
        fetchResult.error || `${fetchResult.bodyLength} bytes`,
      );

      if (fetchResult.error) {
        res.writeHead(500);
        res.end(
          JSON.stringify({ status: "error", message: fetchResult.error }),
        );
        return;
      }

      res.writeHead(200);
      res.end(
        JSON.stringify({
          status: "ok",
          httpStatus: fetchResult.status,
          data: fetchResult.data,
        }),
      );
      return;
    }

    if (url.pathname === "/signature" && req.method === "POST") {
      let body = "";
      for await (const chunk of req) {
        body += chunk;
      }

      let targetUrl = null;
      let userAgent = null;
      let navigateTo = null;

      // Try to parse as JSON first
      try {
        const json = JSON.parse(body);
        if (json.url) targetUrl = json.url;
        if (json.userAgent) userAgent = json.userAgent;
        if (json.navigateTo) navigateTo = json.navigateTo;
      } catch (e) {
        // Body might be a direct URL string
        try {
          new URL(body);
          targetUrl = body;
        } catch (e2) {}
      }

      if (!targetUrl) {
        res.writeHead(400);
        res.end(
          JSON.stringify({
            status: "error",
            message:
              'URL is required in body as JSON { "url": "...", "navigateTo": "...", "userAgent": "..." } or plain text URL',
          }),
        );
        return;
      }

      const result = await generateSignedUrl(targetUrl, userAgent, navigateTo);

      res.writeHead(200);
      res.end(
        JSON.stringify({
          status: "ok",
          data: {
            signed_url: result.signedUrl,
            "x-bogus": result.xBogus,
            "x-gnarly": result.xGnarly,
            "device-id": result.deviceId,
            cookies: result.cookies,
            navigator: {
              user_agent: result.userAgent,
              platform: "MacIntel",
              browser_language: "en-US",
              os: "mac",
              screen_width: "1920",
              screen_height: "1080",
            },
          },
        }),
      );
      return;
    }

    // Restart browser
    if (url.pathname === "/restart") {
      console.log("[Server] Restarting browser...");
      await closeBrowser();
      await initBrowser();
      res.writeHead(200);
      res.end(JSON.stringify({ status: "ok", message: "Browser restarted" }));
      return;
    }

    // ========== ENDPOINT FOLLOW (DÙNG TRÌNH DUYỆT ẢO) ==========
    if (url.pathname === "/follow" && req.method === "POST") {
      let body = "";
      for await (const chunk of req) body += chunk;

      let username, cookie;
      try {
        const json = JSON.parse(body);
        username = json.username;
        cookie = json.cookie;
      } catch (e) {
        res.writeHead(400);
        res.end(JSON.stringify({ status: "error", message: "Invalid JSON" }));
        return;
      }

      if (!username || !cookie) {
        res.writeHead(400);
        res.end(JSON.stringify({ status: "error", message: "Thiếu username hoặc cookie" }));
        return;
      }

      // Dùng tab riêng biệt — tránh conflict với session SDK
      let followPage = null;
      try {
        await initBrowser();

        followPage = await browser.newPage();
        await followPage.setUserAgent(DEFAULT_UA);
        await followPage.setViewport({ width: 1920, height: 1080 });

        // Chặn ảnh/media để load nhanh hơn
        await followPage.setRequestInterception(true);
        followPage.on("request", (r) => {
          if (["image", "media", "font"].includes(r.resourceType())) r.abort();
          else r.continue();
        });

        // Parse cookie string → array
        const cookieArray = [];
        for (const part of cookie.split(";")) {
          const p = part.trim();
          const idx = p.indexOf("=");
          if (idx === -1) continue;
          const name = p.slice(0, idx).trim();
          const value = p.slice(idx + 1).trim();
          if (!name) continue;
          cookieArray.push({
            name, value,
            domain: ".tiktok.com",
            path: "/",
            httpOnly: false,
            secure: true,
            sameSite: "None"
          });
        }

        // BƯỚC 1: Vào trang chủ TikTok trước để set cookie đúng domain
        // FIX: Bọc goto trong try/catch — timeout là bình thường trên Render
        try {
          await followPage.goto("https://www.tiktok.com/", {
            waitUntil: "domcontentloaded",
            timeout: 30000
          });
        } catch (e) {
          console.log(`[Follow] goto trang chủ timeout (bỏ qua): ${e.message}`);
        }
        await new Promise(r => setTimeout(r, 2000));

        if (cookieArray.length > 0) {
          await followPage.setCookie(...cookieArray);
          console.log(`[Follow] Set ${cookieArray.length} cookies vào tab mới`);
        }

        // Bắt response follow API
        let followResponse = null;
        followPage.on("response", (r) => {
          if (r.url().includes("commit/follow/user")) followResponse = r;
        });

        // BƯỚC 2: Navigate tới profile sau khi đã có cookie
        // FIX: Bọc goto trong try/catch — TikTok SPA thường không resolve đúng hạn trên Render
        console.log(`[Follow] Navigating to https://www.tiktok.com/@${username}...`);
        try {
          await followPage.goto(`https://www.tiktok.com/@${username}`, {
            waitUntil: "domcontentloaded",
            timeout: 30000
          });
        } catch (e) {
          console.log(`[Follow] goto profile timeout (bỏ qua): ${e.message}`);
        }
        // Chờ thêm để React render
        await new Promise(r => setTimeout(r, 3000));

        const pageTitle = await followPage.title();
        const currentUrl = followPage.url();
        console.log(`[Follow] Title: "${pageTitle}" | URL: ${currentUrl}`);

        // Kiểm tra bị redirect về landing page hay không
        if (!currentUrl.includes(`@${username}`)) {
          throw new Error(`Cookie không hợp lệ hoặc hết hạn — bị redirect về: ${currentUrl}`);
        }

        // Tìm nút Follow — nhiều selector dự phòng
        // Không dùng setTimeout cố định — waitForSelector tự chờ React render
        const SELECTORS = [
          'button[data-e2e="follow-button"]',
          'button[data-e2e="followButton"]',
          '[data-e2e="follow-button"]',
          '[data-e2e="followButton"]',
        ];

        let followButton = null;
        let usedSelector = null;

        for (const sel of SELECTORS) {
          try {
            followButton = await followPage.waitForSelector(sel, { timeout: 15000 });
            if (followButton) { usedSelector = sel; break; }
          } catch (_) {}
        }

        // Fallback: scan toàn bộ button theo text
        if (!followButton) {
          console.log(`[Follow] Selector không khớp, đang scan text button...`);
          followButton = await followPage.evaluateHandle(() =>
            Array.from(document.querySelectorAll("button"))
              .find(b => /^\s*(Follow|Follow Back)\s*$/i.test(b.innerText || "")) || null
          );
          const isNull = await followPage.evaluate(el => el === null, followButton);
          if (isNull) { followButton = null; } else { usedSelector = "text-scan"; }
        }

        // Log tất cả button để debug
        const allButtons = await followPage.evaluate(() =>
          Array.from(document.querySelectorAll("button"))
            .map(b => ({ e2e: b.getAttribute("data-e2e"), text: (b.innerText || "").trim().substring(0, 40) }))
        );
        console.log(`[Follow] All buttons:`, JSON.stringify(allButtons));

        if (!followButton) {
          res.writeHead(500);
          res.end(JSON.stringify({
            ok: false,
            error: "Không tìm thấy nút Follow",
            message: "Trang chưa load đủ hoặc TikTok thay đổi selector",
            debug: { pageTitle, currentUrl, allButtons }
          }));
          return;
        }

        const buttonText = await followPage.evaluate(el => (el.innerText || "").trim(), followButton);
        console.log(`[Follow] Button: "${buttonText}" (selector: ${usedSelector})`);

        if (!buttonText.toLowerCase().includes("follow")) {
          res.writeHead(200);
          res.end(JSON.stringify({
            ok: false,
            error: `Nút không phải Follow ("${buttonText}")`,
            message: "Có thể đã follow trước đó hoặc cookie của tài khoản khác",
            debug: { pageTitle, buttonText }
          }));
          return;
        }

        await followButton.click();
        console.log(`[Follow] Clicked Follow button`);

        // Chờ response API tối đa 8 giây
        const waitStart = Date.now();
        while (!followResponse && Date.now() - waitStart < 8000) {
          await new Promise(r => setTimeout(r, 200));
        }

        if (followResponse) {
          let respBody = "";
          try { respBody = await followResponse.text(); } catch (_) {}
          const statusCode = followResponse.status();
          console.log(`[Follow] API HTTP ${statusCode}: ${respBody.substring(0, 300)}`);

          let parsedData = null;
          try { parsedData = JSON.parse(respBody); } catch (_) {}

          res.writeHead(200);
          res.end(JSON.stringify({
            ok: statusCode === 200,
            status_code: statusCode,
            raw: respBody.substring(0, 300),
            data: parsedData,
            message: statusCode === 200 ? "Follow thành công" : `Lỗi HTTP ${statusCode}`
          }));
        } else {
          // Không bắt được API response — kiểm tra nút có đổi text không
          const newButtonText = await followPage.evaluate(
            el => (el.innerText || "").trim(), followButton
          ).catch(() => "unknown");
          console.log(`[Follow] No API response. New button text: "${newButtonText}"`);
          const likelySuccess = /following|unfollow/i.test(newButtonText);
          res.writeHead(likelySuccess ? 200 : 500);
          res.end(JSON.stringify({
            ok: likelySuccess,
            error: likelySuccess ? null : "Không nhận được phản hồi từ API follow",
            message: likelySuccess
              ? `Có vẻ đã follow (nút đổi thành "${newButtonText}")`
              : "Bị chặn, CAPTCHA hoặc chưa đăng nhập đúng tài khoản",
            debug: { newButtonText }
          }));
        }

      } catch (e) {
        console.error("[Follow] Lỗi:", e.message);
        res.writeHead(500);
        res.end(JSON.stringify({ ok: false, error: e.message, message: "Lỗi server khi follow" }));
      } finally {
        // Luôn đóng tab follow để giải phóng bộ nhớ
        if (followPage) {
          try { await followPage.close(); } catch (_) {}
          console.log(`[Follow] Tab đã đóng`);
        }
      }
      return;
    }


    // ========== ENDPOINT FOLLOW-FROM-TOOL ==========
    // Nhận cookie + target_url (link profile TikTok) từ tool bên ngoài
    // Đăng nhập bằng cookie rồi follow tài khoản trong link
    if (url.pathname === "/follow-from-tool" && req.method === "POST") {
      let body = "";
      for await (const chunk of req) body += chunk;

      let cookie, targetUrl, username;
      try {
        const json = JSON.parse(body);
        cookie = json.cookie;
        // Chấp nhận target_url hoặc username
        targetUrl = json.target_url || json.targetUrl || null;
        username = json.username || null;

        // Nếu truyền target_url dạng https://www.tiktok.com/@username thì tách username
        if (targetUrl && !username) {
          const m = targetUrl.match(/@([^/?&]+)/);
          if (m) username = m[1];
        }
        // Nếu truyền username thì tạo targetUrl
        if (username && !targetUrl) {
          targetUrl = `https://www.tiktok.com/@${username}`;
        }
      } catch (e) {
        res.writeHead(400);
        res.end(JSON.stringify({ status: "error", message: "Invalid JSON. Cần: { cookie, target_url } hoặc { cookie, username }" }));
        return;
      }

      if (!cookie || !username) {
        res.writeHead(400);
        res.end(JSON.stringify({
          status: "error",
          message: "Thiếu tham số. Cần: cookie (string) và target_url (https://www.tiktok.com/@username) hoặc username"
        }));
        return;
      }

      console.log(`[FollowTool] Nhận yêu cầu follow @${username}`);

      let followPage = null;
      try {
        await initBrowser();

        followPage = await browser.newPage();
        await followPage.setUserAgent(DEFAULT_UA);
        await followPage.setViewport({ width: 1920, height: 1080 });

        // Block ảnh/media/font/css để tránh Chrome hết RAM crash (chrome-error://chromewebdata/)
        // Chú ý: KHÔNG block XHR/fetch vì cần gọi API follow
        await followPage.setRequestInterception(true);
        followPage.on("request", (r) => {
          const rt = r.resourceType();
          if (["image", "media", "font", "stylesheet"].includes(rt)) {
            r.abort();
          } else {
            r.continue();
          }
        });

        // Parse cookie string → array
        const cookieArray = [];
        for (const part of cookie.split(";")) {
          const p = part.trim();
          const idx = p.indexOf("=");
          if (idx === -1) continue;
          const name = p.slice(0, idx).trim();
          const value = p.slice(idx + 1).trim();
          if (!name) continue;
          cookieArray.push({
            name, value,
            domain: ".tiktok.com",
            path: "/",
            httpOnly: false,
            secure: true,
            sameSite: "None"
          });
        }

        // Bước 1: Navigate trang chủ TikTok TRƯỚC để browser có domain context
        // Sau đó mới set cookie — TikTok yêu cầu session được khởi tạo qua HTTP
        // thì cookie mới được nhận là hợp lệ (CDP set trực tiếp không đủ)
        console.log(`[FollowTool] Bước 1: Navigate trang chủ để khởi tạo session...`);
        try {
          await followPage.goto("https://www.tiktok.com/", {
            waitUntil: "domcontentloaded",
            timeout: 30000
          });
        } catch (e) {
          console.log(`[FollowTool] goto trang chủ timeout (bỏ qua): ${e.message}`);
        }
        await new Promise(r => setTimeout(r, 2000));

        // Bước 2: Set cookie SAU KHI đã có domain context
        if (cookieArray.length > 0) {
          await followPage.setCookie(...cookieArray);
          console.log(`[FollowTool] Set ${cookieArray.length} cookies sau khi navigate trang chủ`);
        }

        // Bắt response follow API
        let followResponse = null;
        followPage.on("response", (r) => {
          if (r.url().includes("commit/follow/user")) followResponse = r;
        });

        // Bước 3: Navigate tới profile với cookie đã được set đúng
        console.log(`[FollowTool] Bước 3: Đang mở ${targetUrl}...`);
        try {
          await followPage.goto(targetUrl, {
            waitUntil: "domcontentloaded",
            timeout: 30000
          });
        } catch (e) {
          console.log(`[FollowTool] goto profile timeout (bỏ qua): ${e.message}`);
        }
        // Chờ thêm để React render sau timeout
        await new Promise(r => setTimeout(r, 3000));

        const pageTitle = await followPage.title();
        const currentUrl = followPage.url();
        console.log(`[FollowTool] Title: "${pageTitle}" | URL: ${currentUrl}`);

        // Kiểm tra bị redirect (cookie hết hạn / sai)
        if (!currentUrl.includes(`@${username}`)) {
          throw new Error(`Cookie không hợp lệ hoặc hết hạn — bị redirect về: ${currentUrl}`);
        }

        // Scroll nhẹ để trigger lazy render của React
        await followPage.evaluate(() => window.scrollBy(0, 300));
        await new Promise(r => setTimeout(r, 1500));

        // Tìm nút Follow — ưu tiên data-e2e chính xác trên profile
        // Timeout 20s vì React cần thêm thời gian sau domcontentloaded
        const SELECTORS = [
          'button[data-e2e="follow-button"]',
          'button[data-e2e="followButton"]',
          '[data-e2e="follow-button"]',
          '[data-e2e="followButton"]',
        ];

        let followButton = null;
        let usedSelector = null;

        for (const sel of SELECTORS) {
          try {
            // Chờ selector xuất hiện
            await followPage.waitForSelector(sel, { timeout: 20000 });
            // Sau đó lấy nút ĐẦU TIÊN — thường là nút trên profile header
            // (các nút trong feed load sau, index cao hơn)
            followButton = await followPage.evaluateHandle((s) => {
              const all = Array.from(document.querySelectorAll(s));
              // Ưu tiên nút nằm cao nhất trên trang (offsetTop nhỏ nhất)
              if (all.length === 0) return null;
              return all.reduce((a, b) => {
                const aTop = a.getBoundingClientRect().top + window.scrollY;
                const bTop = b.getBoundingClientRect().top + window.scrollY;
                return aTop <= bTop ? a : b;
              });
            }, sel);
            const isNull = await followPage.evaluate(el => el === null, followButton);
            if (!isNull) { usedSelector = sel; break; }
          } catch (_) {}
        }

        // Fallback: tìm đúng nút Follow của PROFILE (không phải suggested feed)
        if (!followButton) {
          followButton = await followPage.evaluateHandle(() => {
            // Chiến lược 1: tìm trong vùng share-info / profile header
            const profileArea = document.querySelector(
              '[data-e2e="user-page"], [class*="ShareInfo"], [class*="profile-header"], [class*="userInfo"], main'
            );
            if (profileArea) {
              const btn = profileArea.querySelector('[data-e2e="follow-button"], [data-e2e="followButton"]');
              if (btn) return btn;
            }
            // Chiến lược 2: lấy nút follow-button ĐẦU TIÊN trên trang (trước feed)
            const first = document.querySelector('[data-e2e="follow-button"], [data-e2e="followButton"]');
            if (first) return first;
            return null;
          });
          const isNull = await followPage.evaluate(el => el === null, followButton);
          if (isNull) { followButton = null; } else { usedSelector = "evaluate-fallback"; }
        }

        // Debug: log tất cả button
        const allButtons = await followPage.evaluate(() =>
          Array.from(document.querySelectorAll("button"))
            .map(b => ({ e2e: b.getAttribute("data-e2e"), text: (b.innerText || "").trim().substring(0, 40) }))
        );
        console.log(`[FollowTool] Buttons:`, JSON.stringify(allButtons));

        if (!followButton) {
          res.writeHead(500);
          res.end(JSON.stringify({
            ok: false,
            error: "Không tìm thấy nút Follow",
            message: "Trang chưa render đủ hoặc TikTok thay đổi selector",
            debug: { pageTitle, currentUrl, allButtons }
          }));
          return;
        }

        const buttonText = await followPage.evaluate(el => (el.innerText || "").trim(), followButton);
        console.log(`[FollowTool] Nút: "${buttonText}" (selector: ${usedSelector})`);

        // Kiểm tra đã follow chưa
        if (/following|unfollow/i.test(buttonText)) {
          res.writeHead(200);
          res.end(JSON.stringify({
            ok: true,
            already_followed: true,
            message: `Đã follow @${username} trước đó rồi`,
            button_text: buttonText
          }));
          return;
        }

        if (!buttonText.toLowerCase().includes("follow")) {
          res.writeHead(200);
          res.end(JSON.stringify({
            ok: false,
            error: `Nút không phải Follow ("${buttonText}")`,
            message: "Cookie có thể thuộc tài khoản khác hoặc chưa đăng nhập",
            debug: { pageTitle, buttonText }
          }));
          return;
        }

        // Lấy secUid từ trang để gọi API follow trực tiếp
        console.log(`[FollowTool] Đang lấy secUid của @${username}...`);
        const secUid = await followPage.evaluate(() => {
          // Thử lấy từ __NEXT_DATA__ (SSR data)
          try {
            const nd = window.__NEXT_DATA__;
            if (nd) {
              const ud = nd.props?.pageProps?.userInfo?.user?.secUid
                || nd.props?.pageProps?.userDetails?.user?.secUid;
              if (ud) return ud;
            }
          } catch (_) {}
          // Thử lấy từ SIGI_STATE
          try {
            const ss = window.__SIGI_STATE__;
            if (ss) {
              const users = ss.UserModule?.users || ss.userModule?.users || {};
              const keys = Object.keys(users);
              if (keys.length > 0) return users[keys[0]].secUid || null;
            }
          } catch (_) {}
          // Thử lấy từ meta tag hoặc JSON-LD
          try {
            const scripts = Array.from(document.querySelectorAll('script[type="application/json"]'));
            for (const s of scripts) {
              const txt = s.textContent || "";
              const m = txt.match(/"secUid"\s*:\s*"([^"]+)"/);
              if (m) return m[1];
            }
          } catch (_) {}
          return null;
        });

        console.log(`[FollowTool] secUid: ${secUid ? secUid.substring(0, 30) + "..." : "không tìm thấy"}`);

        if (!secUid) {
          // Fallback: click nút nếu không lấy được secUid
          console.log(`[FollowTool] Không có secUid, fallback click nút...`);
          await followButton.click();
          await new Promise(r => setTimeout(r, 5000));
          const newText = await followPage.evaluate(
            el => (el.innerText || "").trim(), followButton
          ).catch(() => "unknown");
          const likelySuccess = /following|unfollow/i.test(newText);
          res.writeHead(likelySuccess ? 200 : 500);
          res.end(JSON.stringify({
            ok: likelySuccess,
            target_username: username,
            target_url: targetUrl,
            message: likelySuccess
              ? `Follow @${username} thành công (nút đổi thành "${newText}")`
              : "Không lấy được secUid và click cũng không thành công",
            debug: { newButtonText: newText, secUid: null }
          }));
          return;
        }

        // Lấy cookie + msToken từ followPage để dùng cho request có signature
        const followCookies = await followPage.cookies();
        const followCookieStr = followCookies.map(c => `${c.name}=${c.value}`).join("; ");
        const msTokenMatch2 = followCookieStr.match(/msToken=([^;]+)/);
        const msToken2 = msTokenMatch2 ? msTokenMatch2[1] : "";

        // Build URL follow API cần ký
        const followApiParams = new URLSearchParams({
          secUid: secUid,
          from: "0",
          from_pre: "0",
          enter_from: "user_profile",
          action_type: "0",
          aid: "1988",
          app_language: "en",
          app_name: "tiktok_web",
          browser_language: "en-US",
          browser_name: "Mozilla",
          browser_online: "true",
          browser_platform: "MacIntel",
          browser_version: "5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15",
          channel: "tiktok_web",
          cookie_enabled: "true",
          device_platform: "web_pc",
          focus_state: "true",
          from_page: "user",
          history_len: "3",
          is_fullscreen: "false",
          is_page_visible: "true",
          os: "mac",
          priority_region: "",
          referer: "",
          region: "VN",
          screen_height: "1080",
          screen_width: "1920",
          webcast_language: "en",
          msToken: msToken2,
        });

        const unsignedFollowUrl = `https://www.tiktok.com/api/commit/follow/user/?${followApiParams.toString()}`;
        console.log(`[FollowTool] Ký URL follow...`);

        // Ký URL qua SDK trên main page
        let signedFollowUrl = null;
        try {
          const signResult = await generateSignedUrl(unsignedFollowUrl, null, null);
          signedFollowUrl = signResult.signedUrl;
          console.log(`[FollowTool] URL đã ký: ${signedFollowUrl.substring(0, 100)}...`);
        } catch (signErr) {
          console.log(`[FollowTool] Ký URL lỗi: ${signErr.message}, dùng URL chưa ký`);
          signedFollowUrl = unsignedFollowUrl;
        }

        // Gọi API follow từ trong followPage context (đúng cookie + session TikTok)
        console.log(`[FollowTool] Gọi API follow có signature...`);
        const apiResult = await followPage.evaluate(async ({ signedUrl, cookieStr }) => {
          try {
            // Lấy CSRF token từ cookie tt_csrf_token (bắt buộc với TikTok API)
            const csrfMatch = document.cookie.match(/tt_csrf_token=([^;]+)/);
            const csrfToken = csrfMatch ? decodeURIComponent(csrfMatch[1]) : "";

            const resp = await fetch(signedUrl, {
              method: "POST",
              credentials: "include",
              headers: {
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": "0",
                "Referer": "https://www.tiktok.com/",
                "Origin": "https://www.tiktok.com",
                "X-CSRFToken": csrfToken,
              },
            });
            const text = await resp.text();
            let data = null;
            try { data = JSON.parse(text); } catch (_) {}
            return { status: resp.status, text: text.substring(0, 500), data };
          } catch (e) {
            return { error: e.message };
          }
        }, { signedUrl: signedFollowUrl, cookieStr: followCookieStr });

        console.log(`[FollowTool] API result: ${JSON.stringify(apiResult).substring(0, 300)}`);

        if (apiResult.error) {
          res.writeHead(500);
          res.end(JSON.stringify({
            ok: false,
            error: apiResult.error,
            target_username: username,
            message: "Lỗi khi gọi API follow"
          }));
        } else {
          // TikTok trả data.status_code === 0 là thành công, hoặc body rỗng cũng ok
          const tiktokCode = apiResult.data?.status_code;
          const success = apiResult.status === 200 && (tiktokCode === 0 || tiktokCode === undefined);
          res.writeHead(200);
          res.end(JSON.stringify({
            ok: success,
            status_code: apiResult.status,
            tiktok_status_code: tiktokCode,
            target_username: username,
            target_url: targetUrl,
            data: apiResult.data,
            raw: apiResult.text,
            message: success
              ? `Follow @${username} thành công`
              : `TikTok từ chối: status_code=${tiktokCode}`
          }));
        }

      } catch (e) {
        console.error("[FollowTool] Lỗi:", e.message);
        res.writeHead(500);
        res.end(JSON.stringify({
          ok: false,
          error: e.message,
          message: "Lỗi server khi thực hiện follow"
        }));
      } finally {
        if (followPage) {
          try { await followPage.close(); } catch (_) {}
          console.log(`[FollowTool] Tab đã đóng`);
        }
      }
      return;
    }

    // 404
    res.writeHead(404);
    res.end(JSON.stringify({ error: "Not found" }));
  } catch (e) {
    console.error("[Server] Error:", e.message);
    res.writeHead(500);
    res.end(JSON.stringify({ status: "error", message: e.message }));
  }
}

// Create server
const server = http.createServer(handleRequest);

server.listen(PORT, () => {
  console.log(`[Server] TikTok Signature Server running on port ${PORT}`);
  console.log(`[Server] Endpoints:`);
  console.log(
    `  POST /signature - Generate signed URL (RECOMMENDED for scalability)`,
  );
  console.log(
    `  POST /fetch     - Fetch through browser (fallback, 100% reliable)`,
  );
  console.log(`  GET  /health    - Health check`);
  console.log(`  GET  /restart   - Restart browser session`);
  console.log(`  POST /follow-from-tool - Follow từ tool ngoài (cookie + target_url)`);

  // Initialize browser on startup
  initBrowser().catch((e) => console.error("[Server] Init failed:", e.message));
});

// Graceful shutdown
process.on("SIGINT", async () => {
  console.log("\n[Server] Shutting down...");
  await closeBrowser();
  process.exit(0);
});

process.on("SIGTERM", async () => {
  console.log("\n[Server] Received SIGTERM, shutting down...");
  await closeBrowser();
  process.exit(0);
});
