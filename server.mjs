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

      // Timeout cứng cho toàn bộ logic follow (60 giây)
      const FOLLOW_TIMEOUT_MS = 60000;

      const executeFollowLogic = async () => {
        let followPage = null;
        try {
          await initBrowser();

          followPage = await browser.newPage();
          await followPage.setUserAgent(DEFAULT_UA);
          await followPage.setViewport({ width: 1920, height: 1080 });

          // Block ảnh/media
          await followPage.setRequestInterception(true);
          followPage.on("request", (r) => {
            if (["image", "media", "font"].includes(r.resourceType())) r.abort();
            else r.continue();
          });

          // Parse cookie
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

          // Vào trang chủ để gán cookie
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

          // Vào trang profile
          console.log(`[Follow] Navigating to https://www.tiktok.com/@${username}...`);
          try {
            await followPage.goto(`https://www.tiktok.com/@${username}`, {
              waitUntil: "domcontentloaded",
              timeout: 30000
            });
          } catch (e) {
            console.log(`[Follow] goto profile timeout (bỏ qua): ${e.message}`);
          }

          // Chờ khung profile chính xuất hiện (đảm bảo React render xong)
          await followPage.waitForSelector('[data-e2e="user-page"]', { timeout: 15000 }).catch(() => {});
          await new Promise(r => setTimeout(r, 2000));

          const pageTitle = await followPage.title();
          const currentUrl = followPage.url();
          console.log(`[Follow] Title: "${pageTitle}" | URL: ${currentUrl}`);

          if (!currentUrl.includes(`@${username}`)) {
            throw new Error(`Cookie không hợp lệ hoặc hết hạn — bị redirect về: ${currentUrl}`);
          }

          // Danh sách selector mở rộng cho nút Follow (cập nhật 2025)
          const SELECTORS = [
            'button[data-e2e="follow-button"]',
            'button[data-e2e="follow-btn"]',
            'button[aria-label*="Follow"]',
            '[data-e2e="follow-btn"]',
            'div[data-e2e="user-page"] button:has-text("Follow")',
          ];

          let followButton = null;
          let usedSelector = null;
          for (const sel of SELECTORS) {
            try {
              followButton = await followPage.waitForSelector(sel, { timeout: 5000 });
              if (followButton) { usedSelector = sel; break; }
            } catch (_) {}
          }

          // Fallback text scan
          if (!followButton) {
            console.log(`[Follow] Selector không khớp, đang scan text button...`);
            followButton = await followPage.evaluateHandle(() => {
              const all = document.querySelectorAll('button, [role="button"]');
              for (const el of all) {
                const text = (el.innerText || '').trim();
                if (/^\s*(Follow|Follow Back|Theo dõi)\s*$/i.test(text)) return el;
                // Kiểm tra aria-label
                if (/follow/i.test(el.getAttribute('aria-label') || '')) return el;
              }
              return null;
            });
            const isNull = await followPage.evaluate(el => el === null, followButton);
            if (isNull) followButton = null; else usedSelector = "text-scan";
          }

          // Log tất cả button để debug
          const allButtons = await followPage.evaluate(() =>
            Array.from(document.querySelectorAll("button"))
              .map(b => ({ e2e: b.getAttribute("data-e2e"), text: (b.innerText || "").trim().substring(0, 40) }))
          );
          console.log(`[Follow] All buttons:`, JSON.stringify(allButtons));

          if (!followButton) {
            return {
              ok: false,
              error: "Không tìm thấy nút Follow",
              message: "Trang chưa load đủ hoặc TikTok thay đổi selector",
              debug: { pageTitle, currentUrl, allButtons }
            };
          }

          const buttonText = await followPage.evaluate(el => (el.innerText || "").trim(), followButton);
          console.log(`[Follow] Button: "${buttonText}" (selector: ${usedSelector})`);

          if (!buttonText.toLowerCase().includes("follow")) {
            return {
              ok: false,
              error: `Nút không phải Follow ("${buttonText}")`,
              message: "Có thể đã follow trước đó hoặc cookie của tài khoản khác",
              debug: { pageTitle, buttonText }
            };
          }

          await followButton.click();
          console.log(`[Follow] Clicked Follow button`);

          // Chờ response API
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

            return {
              ok: statusCode === 200,
              status_code: statusCode,
              raw: respBody.substring(0, 300),
              data: parsedData,
              message: statusCode === 200 ? "Follow thành công" : `Lỗi HTTP ${statusCode}`
            };
          } else {
            const newButtonText = await followPage.evaluate(
              el => (el.innerText || "").trim(), followButton
            ).catch(() => "unknown");
            console.log(`[Follow] No API response. New button text: "${newButtonText}"`);
            const likelySuccess = /following|unfollow/i.test(newButtonText);
            return {
              ok: likelySuccess,
              error: likelySuccess ? null : "Không nhận được phản hồi từ API follow",
              message: likelySuccess
                ? `Có vẻ đã follow (nút đổi thành "${newButtonText}")`
                : "Bị chặn, CAPTCHA hoặc chưa đăng nhập đúng tài khoản",
              debug: { newButtonText }
            };
          }
        } catch (e) {
          console.error("[Follow] Lỗi:", e.message);
          return { ok: false, error: e.message, message: "Lỗi server khi follow" };
        } finally {
          if (followPage) {
            try { await followPage.close(); } catch (_) {}
            console.log(`[Follow] Tab đã đóng`);
          }
        }
      };

      // Đua logic với timeout để tránh treo vĩnh viễn
      try {
        const result = await Promise.race([
          executeFollowLogic(),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error("Follow logic timeout")), FOLLOW_TIMEOUT_MS)
          )
        ]);
        res.writeHead(result.ok ? 200 : 500);
        res.end(JSON.stringify(result));
      } catch (e) {
        console.error("[Follow] Timeout hoặc lỗi:", e.message);
        res.writeHead(500);
        res.end(JSON.stringify({ ok: false, error: e.message, message: "Follow request timeout" }));
      }
      return;
    }

    // ========== ENDPOINT FOLLOW-FROM-TOOL ==========
    // Gọi TikTok mobile API trực tiếp — giả lập TikTok Android app
    if (url.pathname === "/follow-from-tool" && req.method === "POST") {
      let body = "";
      for await (const chunk of req) body += chunk;

      let cookie, targetUrl, username;
      try {
        const json = JSON.parse(body);
        cookie = json.cookie;
        targetUrl = json.target_url || json.targetUrl || null;
        username = json.username || null;
        if (targetUrl && !username) {
          const m = targetUrl.match(/@([^/?&]+)/);
          if (m) username = m[1];
        }
        if (username && !targetUrl) {
          targetUrl = `https://www.tiktok.com/@${username}`;
        }
      } catch (e) {
        res.writeHead(400);
        res.end(JSON.stringify({ status: "error", message: "Invalid JSON" }));
        return;
      }

      if (!cookie || !username) {
        res.writeHead(400);
        res.end(JSON.stringify({ status: "error", message: "Thiếu cookie hoặc username/target_url" }));
        return;
      }

      console.log(`[FollowTool] Nhận yêu cầu follow @${username}`);

      // Timeout cứng 90 giây
      const TOOL_TIMEOUT_MS = 90000;

      const executeToolLogic = async () => {
        let followPage = null;
        try {
          // Parse cookie string → object
          const cookieObj = {};
          for (const part of cookie.split(";")) {
            const p = part.trim();
            const idx = p.indexOf("=");
            if (idx === -1) continue;
            cookieObj[p.slice(0, idx).trim()] = p.slice(idx + 1).trim();
          }

          const sessionid = cookieObj["sessionid"] || "";
          const msToken = (() => {
            const all = cookie.match(/msToken=([^;]+)/g) || [];
            return all.length ? all[all.length - 1].split("=").slice(1).join("=") : "";
          })();
          const csrfToken = cookieObj["tt_csrf_token"] || "";
          const verifyFp = cookieObj["s_v_web_id"] || "";
          const deviceId = cookieObj["odin_tt"] ? "7629627162782778888" : "";

          if (!sessionid) {
            return { ok: false, error: "Không tìm thấy sessionid trong cookie" };
          }

          // Tạo followPage sớm để navigate song song
          followPage = await browser.newPage();
          await followPage.setUserAgent(DEFAULT_UA);
          await followPage.setViewport({ width: 1920, height: 1080 });

          // Block resource nặng qua CDP
          const cdpSession = await followPage.createCDPSession();
          await cdpSession.send("Network.enable");
          await cdpSession.send("Network.setBlockedURLs", {
            urls: ["*.jpg","*.jpeg","*.png","*.gif","*.webp","*.svg",
                   "*.mp4","*.webm","*.mp3","*.woff","*.woff2","*.ttf","*.css"]
          });

          // Set cookie trước
          const cookieArray = [];
          for (const part of cookie.split(";")) {
            const p = part.trim();
            const eq = p.indexOf("=");
            if (eq === -1) continue;
            const name = p.slice(0, eq).trim();
            const value = p.slice(eq + 1).trim();
            if (!name) continue;
            cookieArray.push({ name, value, domain: ".tiktok.com", path: "/", secure: true, sameSite: "None" });
          }

          // Navigate trang chủ để init session
          console.log(`[FollowTool] Bước 1: Navigate trang chủ để khởi tạo session...`);
          try {
            await followPage.goto("https://www.tiktok.com/", { waitUntil: "domcontentloaded", timeout: 30000 });
          } catch (e) {
            console.log(`[FollowTool] goto trang chủ timeout (bỏ qua): ${e.message}`);
          }
          await new Promise(r => setTimeout(r, 2000));

          if (cookieArray.length > 0) {
            await followPage.setCookie(...cookieArray);
            console.log(`[FollowTool] Set ${cookieArray.length} cookies`);
          }

          // Navigate tới profile
          console.log(`[FollowTool] Bước 2: Đang mở ${targetUrl}...`);
          try {
            await followPage.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: 30000 });
          } catch (e) {
            console.log(`[FollowTool] goto profile timeout (bỏ qua): ${e.message}`);
          }

          // Chờ user-page
          await followPage.waitForSelector('[data-e2e="user-page"]', { timeout: 15000 }).catch(() => {});
          await new Promise(r => setTimeout(r, 2000));

          const pageTitle = await followPage.title();
          const currentUrl = followPage.url();
          console.log(`[FollowTool] Title: "${pageTitle}" | URL: ${currentUrl}`);

          if (!currentUrl.includes(`@${username}`)) {
            return { ok: false, error: `Cookie không hợp lệ hoặc hết hạn — bị redirect về: ${currentUrl}` };
          }

          // Lấy secUid từ page data
          console.log(`[FollowTool] Lấy secUid từ page data...`);
          const secUid = await followPage.evaluate((uname) => {
            // Thử __SIGI_STATE__
            try {
              const ss = window.__SIGI_STATE__;
              if (ss) {
                const users = ss.UserModule?.users || ss.userModule?.users || {};
                for (const [key, u] of Object.entries(users)) {
                  if (u.uniqueId?.toLowerCase() === uname.toLowerCase() && u.secUid) return u.secUid;
                }
                const keys = Object.keys(users);
                if (keys.length > 0 && users[keys[0]].secUid) return users[keys[0]].secUid;
              }
            } catch (_) {}
            // Thử __NEXT_DATA__
            try {
              const nd = window.__NEXT_DATA__;
              if (nd) {
                const u = nd.props?.pageProps?.userInfo?.user;
                if (u?.secUid) return u.secUid;
              }
            } catch (_) {}
            // Thử meta/script tags
            try {
              for (const s of document.querySelectorAll('script')) {
                const txt = s.textContent || "";
                const m = txt.match(/"secUid"\s*:\s*"(MS4[^"]+)"/);
                if (m) return m[1];
              }
            } catch (_) {}
            return null;
          }, username);

          console.log(`[FollowTool] secUid: ${secUid ? secUid.substring(0, 30) + "..." : "không tìm thấy"}`);

          if (!secUid) {
            return { ok: false, error: `Không lấy được secUid của @${username}` };
          }

          // Scroll nhẹ để trigger lazy render
          await followPage.evaluate(() => window.scrollBy(0, 300));
          await new Promise(r => setTimeout(r, 1500));

          // Tìm nút Follow với selector cập nhật
          const SELECTORS = [
            'button[data-e2e="follow-button"]',
            'button[data-e2e="follow-btn"]',
            'button[aria-label*="Follow"]',
            '[data-e2e="follow-btn"]',
          ];

          let followButton = null;
          let usedSelector = null;
          for (const sel of SELECTORS) {
            try {
              followButton = await followPage.waitForSelector(sel, { timeout: 5000 });
              if (followButton) { usedSelector = sel; break; }
            } catch (_) {}
          }

          if (!followButton) {
            // Fallback text scan
            followButton = await followPage.evaluateHandle(() => {
              const all = document.querySelectorAll('button, [role="button"]');
              for (const el of all) {
                if (/^\s*(Follow|Follow Back|Theo dõi)\s*$/i.test((el.innerText || '').trim())) return el;
                if (/follow/i.test(el.getAttribute('aria-label') || '')) return el;
              }
              return null;
            });
            const isNull = await followPage.evaluate(el => el === null, followButton);
            if (isNull) followButton = null; else usedSelector = "text-scan";
          }

          const allButtons = await followPage.evaluate(() =>
            Array.from(document.querySelectorAll("button"))
              .map(b => ({ e2e: b.getAttribute("data-e2e"), text: (b.innerText||"").trim().substring(0,30) }))
          );
          console.log(`[FollowTool] Buttons: ${JSON.stringify(allButtons).substring(0, 200)}`);

          if (!followButton) {
            return { ok: false, error: "Không tìm thấy nút Follow", debug: { allButtons } };
          }

          const buttonText = await followPage.evaluate(el => (el.innerText||"").trim(), followButton);
          console.log(`[FollowTool] Nút: "${buttonText}" (${usedSelector})`);

          if (/following|unfollow/i.test(buttonText)) {
            return { ok: true, already_followed: true, message: `Đã follow @${username} rồi` };
          }

          if (!buttonText.toLowerCase().includes("follow")) {
            return { ok: false, error: `Nút không phải Follow: "${buttonText}"` };
          }

          // Đăng ký bắt response TRƯỚC khi click
          const followApiPromise = followPage.waitForResponse(
            r => r.url().includes("commit/follow/user"),
            { timeout: 20000 }
          ).catch(() => null);

          // Click với đầy đủ mouse events
          console.log(`[FollowTool] Click Follow...`);
          await followPage.evaluate(el => {
            ['mousedown','mouseup','click'].forEach(type =>
              el.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true }))
            );
          }, followButton);

          console.log(`[FollowTool] Đã click, chờ API response...`);
          const followResponse2 = await followApiPromise;

          if (followResponse2) {
            let respBody = "";
            try { respBody = await followResponse2.text(); } catch (_) {}
            const statusCode = followResponse2.status();
            let parsedData = null;
            try { parsedData = JSON.parse(respBody); } catch (_) {}
            const tiktokCode = parsedData?.status_code;
            const success = statusCode === 200 && (tiktokCode === 0 || tiktokCode === undefined);
            console.log(`[FollowTool] API HTTP ${statusCode}, tiktok_code=${tiktokCode}`);
            return {
              ok: success,
              status_code: statusCode,
              tiktok_status_code: tiktokCode,
              target_username: username,
              target_url: targetUrl,
              data: parsedData,
              message: success ? `Follow @${username} thành công` : `TikTok từ chối: ${tiktokCode}`
            };
          } else {
            const newText = await followPage.evaluate(el => (el.innerText||"").trim(), followButton).catch(() => "unknown");
            const likelySuccess = /following|unfollow/i.test(newText);
            console.log(`[FollowTool] Không bắt được API. Nút mới: "${newText}"`);
            return {
              ok: likelySuccess,
              target_username: username,
              target_url: targetUrl,
              message: likelySuccess ? `Follow @${username} thành công (nút: "${newText}")` : "Không nhận được API response",
              debug: { newButtonText: newText }
            };
          }
        } catch (e) {
          console.error("[FollowTool] Lỗi:", e.message);
          return { ok: false, error: e.message, message: "Lỗi server" };
        } finally {
          if (typeof followPage !== "undefined" && followPage) {
            try { await followPage.close(); } catch (_) {}
            console.log(`[FollowTool] Tab đã đóng`);
          }
          try { if (typeof cdpSession !== "undefined") await cdpSession.detach(); } catch (_) {}
        }
      };

      try {
        const result = await Promise.race([
          executeToolLogic(),
          new Promise((_, reject) => setTimeout(() => reject(new Error("Follow-from-tool timeout")), TOOL_TIMEOUT_MS))
        ]);
        res.writeHead(result.ok ? 200 : 500);
        res.end(JSON.stringify(result));
      } catch (e) {
        console.error("[FollowTool] Timeout/lỗi:", e.message);
        res.writeHead(500);
        res.end(JSON.stringify({ ok: false, error: e.message, message: "Yêu cầu follow quá thời gian chờ" }));
      }
      return;
    }

    // ========== ENDPOINT FOLLOW-APP (MOBILE API + BROWSER) ==========
    if (url.pathname === "/follow-app" && req.method === "POST") {
      let body = "";
      for await (const chunk of req) body += chunk;

      let cookie, username, targetUrl;
      try {
        const json = JSON.parse(body);
        cookie = json.cookie;
        username = json.username || null;
        targetUrl = json.target_url || json.targetUrl || null;
        if (targetUrl && !username) {
          const m = targetUrl.match(/@([^/?&]+)/);
          if (m) username = m[1];
        }
        if (username && !targetUrl) targetUrl = `https://www.tiktok.com/@${username}`;
      } catch (e) {
        res.writeHead(400);
        res.end(JSON.stringify({ ok: false, error: "Invalid JSON" }));
        return;
      }

      if (!cookie || !username) {
        res.writeHead(400);
        res.end(JSON.stringify({ ok: false, error: "Cần cookie và username/target_url" }));
        return;
      }

      console.log(`[FollowApp] Follow @${username} via Mobile API...`);

      let followPage = null;
      try {
        await initBrowser();
        await ensurePageReady();

        // Parse cookie
        const cookieArray = [];
        for (const part of cookie.split(";")) {
          const p = part.trim();
          const eq = p.indexOf("=");
          if (eq === -1) continue;
          const name = p.slice(0, eq).trim();
          const value = p.slice(eq + 1).trim();
          if (name) cookieArray.push({ name, value, domain: ".tiktok.com", path: "/" });
        }

        // Set cookie vào main page để lấy secUid
        try { await page.setCookie(...cookieArray); } catch (_) {}

        // Lấy secUid + userId qua browser
        console.log(`[FollowApp] Lấy user info @${username}...`);
        const userInfo = await page.evaluate(async (uname) => {
          try {
            const r = await fetch(
              `/api/user/detail/?uniqueId=${encodeURIComponent(uname)}&aid=1988&app_name=tiktok_web&device_platform=web_pc`,
              { credentials: "include" }
            );
            const d = await r.json();
            const u = d?.userInfo?.user;
            if (u?.secUid) return { secUid: u.secUid, userId: u.id, nickname: u.nickname };
          } catch (_) {}
          return null;
        }, username);

        if (!userInfo?.secUid) {
          res.writeHead(500);
          res.end(JSON.stringify({ ok: false, error: `Không lấy được secUid @${username}` }));
          return;
        }
        console.log(`[FollowApp] secUid=${userInfo.secUid.substring(0,30)}..., userId=${userInfo.userId}`);

        // Build mobile API params
        const deviceId = "7629627162782778888";
        const ts = Math.floor(Date.now() / 1000);
        const mobileParams = new URLSearchParams({
          user_id: userInfo.userId,
          sec_user_id: userInfo.secUid,
          type: "1",
          from: "21",
          from_pre: "11",
          channel_id: "0",
          os_api: "29",
          device_type: "SM-G991B",
          ssmix: "a",
          manifest_version_code: "2022600030",
          dpi: "420",
          uoo: "0",
          carrier_region: "VN",
          region: "VN",
          app_name: "musical_ly",
          version_name: "22.6.0",
          timezone_offset: "25200",
          ab_version: "22.6.0",
          residence: "VN",
          app_type: "normal",
          ac2: "wifi", ac: "wifi",
          app_version: "22.6.0",
          host_abi: "armeabi-v7a",
          locale: "vi-VN",
          aid: "1233",
          channel: "googleplay",
          timezone_name: "Asia/Ho_Chi_Minh",
          device_platform: "android",
          version_code: "220600",
          sys_region: "VN",
          language: "vi",
          os_version: "13",
          device_id: deviceId,
          cdid: deviceId,
          iid: String(parseInt(deviceId) + 1),
          ts: String(ts),
        });

        const queryStr = mobileParams.toString();

        // Ký X-Gorgon bằng Python nếu có, fallback nếu không
        let sigHeaders = { "X-Gorgon": "", "X-Khronos": String(ts), "X-Argus": "", "X-Ladon": "" };
        try {
          const { execFile } = await import("child_process");
          const { promisify } = await import("util");
          const execFileAsync = promisify(execFile);
          const signerPath = path.join(__dirname, "mobile_signer.py");
          if (fs.existsSync(signerPath)) {
            const input = JSON.stringify({ query: queryStr, ts, device_id: deviceId, cookie: `sessionid=${cookieArray.find(c=>c.name==="sessionid")?.value||""}` });
            const { stdout } = await execFileAsync("python3", ["-c", `
import sys, json
sys.stdin = __import__("io").TextIOWrapper(sys.stdin.buffer)
data = json.loads(sys.stdin.read())
exec(open("${signerPath}").read().split("if __name__")[0])
print(json.dumps(sign(data["query"], data["ts"], data["device_id"], data["cookie"])))
            `], { input, timeout: 8000 });
            sigHeaders = JSON.parse(stdout.trim());
            console.log(`[FollowApp] Signed: X-Gorgon=${sigHeaders["X-Gorgon"]?.substring(0,20)||"(empty)"}...`);
          }
        } catch (sigErr) {
          console.log(`[FollowApp] Sign error: ${sigErr.message}`);
        }

        // Parse sessionid
        const cookieObj = {};
        for (const part of cookie.split(";")) {
          const p = part.trim(); const eq = p.indexOf("=");
          if (eq === -1) continue;
          cookieObj[p.slice(0,eq).trim()] = p.slice(eq+1).trim();
        }
        const sessionid = cookieObj["sessionid"] || "";
        const sessionCookie = `sessionid=${sessionid}; sessionid_ss=${sessionid}; sid_tt=${sessionid}`;

        // Gọi TikTok Mobile API
        const mobileUrl = `https://api16-normal-c-useast1a.tiktokv.com/aweme/v1/commit/follow/user/?${queryStr}`;
        console.log(`[FollowApp] Gọi mobile API...`);

        const https = await import("https");
        const zlib = await import("zlib");
        const mobileResult = await new Promise((resolve) => {
          const reqUrl = new URL(mobileUrl);
          const options = {
            hostname: reqUrl.hostname,
            path: reqUrl.pathname + reqUrl.search,
            method: "POST",
            headers: {
              "Cookie": sessionCookie,
              "User-Agent": "com.zhiliaoapp.musically/2022600030 (Linux; U; Android 13; vi_VN; SM-G991B; Build/TP1A.220624.014; Cronet/TTNetVersion:b4d74d15 2023-04-18 QuicVersion:0144d358 2023-04-09)",
              "Accept": "application/json",
              "Accept-Encoding": "gzip",
              "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
              "Content-Length": "0",
              "X-Gorgon": sigHeaders["X-Gorgon"] || "",
              "X-Khronos": sigHeaders["X-Khronos"] || String(ts),
              "X-Argus": sigHeaders["X-Argus"] || "",
              "X-Ladon": sigHeaders["X-Ladon"] || "",
              "sdk-version": "2",
            },
          };
          const r = https.request(options, (resp) => {
            const chunks = [];
            resp.on("data", d => chunks.push(d));
            resp.on("end", () => {
              let raw = Buffer.concat(chunks);
              try { raw = zlib.gunzipSync(raw); } catch (_) {}
              const text = raw.toString("utf-8");
              try { resolve({ status: resp.statusCode, data: JSON.parse(text), raw: text.substring(0,300) }); }
              catch (_) { resolve({ status: resp.statusCode, data: null, raw: text.substring(0,300) }); }
            });
          });
          r.on("error", e => resolve({ error: e.message }));
          r.setTimeout(20000, () => { r.destroy(); resolve({ error: "timeout" }); });
          r.end();
        });

        console.log(`[FollowApp] Result: ${JSON.stringify(mobileResult).substring(0,300)}`);

        const tiktokCode = mobileResult.data?.status_code;
        const success = mobileResult.status === 200 && (tiktokCode === 0 || tiktokCode === undefined);

        res.writeHead(200);
        res.end(JSON.stringify({
          ok: success,
          status_code: mobileResult.status,
          tiktok_status_code: tiktokCode,
          tiktok_status_msg: mobileResult.data?.status_msg,
          target_username: username,
          user_info: userInfo,
          data: mobileResult.data,
          raw: mobileResult.raw,
          message: success
            ? `Follow @${username} thành công (Mobile API)`
            : mobileResult.error
              ? `Lỗi network: ${mobileResult.error}`
              : `TikTok từ chối: ${tiktokCode} - ${mobileResult.data?.status_msg || ""}`,
        }));

      } catch (e) {
        console.error("[FollowApp] Lỗi:", e.message);
        res.writeHead(500);
        res.end(JSON.stringify({ ok: false, error: e.message }));
      } finally {
        if (followPage) { try { await followPage.close(); } catch (_) {} }
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
  console.log(`  POST /follow-app       - Follow via TikTok mobile API (cookie + username)`);

  // Initialize browser on startup
  initBrowser().catch((e) => console.error("[Server] Init failed:", e.message));

  // Auto-start Python mobile microservice
  (async () => {
    try {
      const { spawn } = await import("child_process");
      const servicePath = path.join(__dirname, "tiktok_mobile_service.py");
      if (fs.existsSync(servicePath)) {
        const svc = spawn("python3", [servicePath], {
          detached: false,
          stdio: ["ignore", "pipe", "pipe"],
          env: { ...process.env, MOBILE_SERVICE_PORT: "8081" },
        });
        svc.stdout.on("data", (d) => process.stdout.write("[PySvc] " + d));
        svc.stderr.on("data", (d) => process.stderr.write("[PySvc] " + d));
        svc.on("exit", (code) => console.log(`[PySvc] Exited with code ${code}`));
        console.log("[Server] Python mobile service started (PID:", svc.pid, ")");
      } else {
        console.log("[Server] tiktok_mobile_service.py not found — /follow-app sẽ không hoạt động");
      }
    } catch (e) {
      console.error("[Server] Không thể khởi động Python service:", e.message);
    }
  })();
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
