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
 * - POST /follow-mobile - Follow user via Mobile API (calls Python signer)
 *
 * Environment Variables:
 * - PORT          - Server port (default: 8080)
 * - PROXY_ENABLED - Enable proxy (default: false)
 * - PROXY_HOST    - Proxy host:port (e.g., "proxy.example.com:8080")
 * - PROXY_USER    - Proxy username
 * - PROXY_PASS    - Proxy password
 */

import http from "http";
import https from "https";
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

// FIX: Dọn dẹp cache định kỳ để tránh memory leak
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of signedUrlCache) {
    if (now - v.capturedAt > SIGNED_CACHE_MAX_AGE_MS) signedUrlCache.delete(k);
  }
}, 60_000);

// Auto-refresh configuration to avoid blocks
const MAX_GENERATIONS_BEFORE_REFRESH = 500;
const MAX_SESSION_AGE_MS = 30 * 60 * 1000;

// Request queue for sequential processing
const requestQueue = [];
let isProcessingQueue = false;

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

async function initBrowser() {
  if (isInitializing) {
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
    const getChromePath = () => {
      if (process.env.PUPPETEER_EXECUTABLE_PATH) {
        return process.env.PUPPETEER_EXECUTABLE_PATH;
      }
      if (process.platform === "darwin") {
        return "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
      }
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
      return undefined;
    };

    const browserArgs = [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-blink-features=AutomationControlled",
      "--disable-gpu",
      "--window-size=1920,1080",
    ];

    if (PROXY_ENABLED) {
      browserArgs.push(`--proxy-server=http://${PROXY_HOST}`);
      console.log(`[Server] Proxy enabled: ${PROXY_HOST}`);
    } else {
      console.log("[Server] Proxy disabled - direct connection");
    }

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

    if (PROXY_ENABLED && PROXY_USER && PROXY_PASS) {
      await page.authenticate({
        username: PROXY_USER,
        password: PROXY_PASS,
      });
    }

    await page.setUserAgent(DEFAULT_UA);
    await page.setViewport({ width: 1920, height: 1080 });

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
    try {
      await page.waitForNavigation({
        waitUntil: "domcontentloaded",
        timeout: 30000,
      });
    } catch (e) {}
    await new Promise((r) => setTimeout(r, 3000));
  }
  return true;
}

async function initWithLocalSdk() {
  if (!localSdkContent) {
    throw new Error(
      "Local SDK not available - ensure webmssdk_5.1.3.js exists in javascript/ folder",
    );
  }

  console.log("[Server] Injecting local SDK before navigation...");

  await page.evaluateOnNewDocument((sdkCode) => {
    try {
      eval(sdkCode);
      console.log("[SDK] Injected via evaluateOnNewDocument");
    } catch (e) {
      console.error("[SDK] Injection error:", e.message);
    }
  }, localSdkContent);

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

    if (
      url.includes("/webmssdk/") ||
      url.includes("slardar") ||
      url.includes("acrawler")
    ) {
      await request.abort();
      return;
    }

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

  console.log("[Server] Waiting for SDK...");
  await new Promise((r) => setTimeout(r, 3000));

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

  console.log("[Server] Warming up SDK...");
  await page.evaluate(() => window.scrollBy(0, 500));
  await new Promise((r) => setTimeout(r, 2000));

  console.log("[Server] Reloading page to stabilize session...");
  try {
    await page.reload({ waitUntil: "domcontentloaded", timeout: 60000 });
  } catch (e) {
    console.log("[Server] Reload warning:", e.message);
  }
  await new Promise((r) => setTimeout(r, 3000));

  await dismissTikTokErrorIfPresent();

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

async function ensurePageReady() {
  try {
    if (!browser || !page) {
      throw new Error("Browser or page not initialized");
    }

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

async function generateSignedUrl(
  targetUrl,
  userAgent = null,
  navigateTo = null,
) {
  return queueSignatureRequest(() =>
    _generateSignedUrlInternal(targetUrl, userAgent, navigateTo),
  );
}

async function _generateSignedUrlInternal(
  targetUrl,
  userAgent = null,
  navigateTo = null,
) {
  await initBrowser();
  await ensurePageReady();

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

  await page.goto(navigateTo, {
    waitUntil: "domcontentloaded",
    timeout: 60000,
  });
  await dismissTikTokErrorIfPresent();

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

function normalizeUrlFingerprint(urlObj) {
  const params = urlObj.searchParams;

  const fingerprint = {
    browser_platform: "MacIntel",
    os: "mac",
    screen_width: "1920",
    screen_height: "1080",
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
    // Health check
    if (url.pathname === "/health") {
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

    // Fetch endpoint
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

    // Signature endpoint
    if (url.pathname === "/signature" && req.method === "POST") {
      let body = "";
      for await (const chunk of req) {
        body += chunk;
      }

      let targetUrl = null;
      let userAgent = null;
      let navigateTo = null;

      try {
        const json = JSON.parse(body);
        if (json.url) targetUrl = json.url;
        if (json.userAgent) userAgent = json.userAgent;
        if (json.navigateTo) navigateTo = json.navigateTo;
      } catch (e) {
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

    // ========== ENDPOINT /follow ==========
    // FIXES:
    //   1. Reload trang chủ SAU KHI set cookie → TikTok nhận đúng session
    //   2. Giảm waitForSelector timeout: 15000 → 5000ms (fail nhanh hơn)
    //   3. Thêm timeout tổng 90s để tránh client timeout 120s
    //   4. Đảm bảo followPage.close() luôn chạy trong finally
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

      let followPage = null;
      // FIX 3: Timeout tổng 90s
      let followTimedOut = false;
      const followTimeoutHandle = setTimeout(() => {
        followTimedOut = true;
        console.log("[Follow] Đã timeout 90s tổng");
      }, 90_000);

      try {
        await initBrowser();

        followPage = await browser.newPage();
        await followPage.setUserAgent(DEFAULT_UA);
        await followPage.setViewport({ width: 1920, height: 1080 });

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

        // BƯỚC 1: Vào trang chủ để set cookie đúng domain
        try {
          await followPage.goto("https://www.tiktok.com/", {
            waitUntil: "domcontentloaded",
            timeout: 20000
          });
        } catch (e) {
          console.log(`[Follow] goto trang chủ timeout (bỏ qua): ${e.message}`);
        }
        await new Promise(r => setTimeout(r, 1000));

        if (cookieArray.length > 0) {
          await followPage.setCookie(...cookieArray);
          console.log(`[Follow] Set ${cookieArray.length} cookies vào tab mới`);
        }

        // FIX 1: Reload sau khi set cookie để TikTok nhận đúng session đăng nhập
        try {
          await followPage.reload({ waitUntil: "domcontentloaded", timeout: 20000 });
          console.log(`[Follow] Reload trang chủ sau khi set cookie`);
        } catch (e) {
          console.log(`[Follow] reload timeout (bỏ qua): ${e.message}`);
        }
        await new Promise(r => setTimeout(r, 2000));

        if (followTimedOut) throw new Error("Follow timed out trước khi navigate profile");

        // Bắt response follow API
        let followResponse = null;
        followPage.on("response", (r) => {
          if (r.url().includes("commit/follow/user")) followResponse = r;
        });

        // BƯỚC 2: Navigate tới profile sau khi đã có session hợp lệ
        console.log(`[Follow] Navigating to https://www.tiktok.com/@${username}...`);
        try {
          await followPage.goto(`https://www.tiktok.com/@${username}`, {
            waitUntil: "domcontentloaded",
            timeout: 25000
          });
        } catch (e) {
          console.log(`[Follow] goto profile timeout (bỏ qua): ${e.message}`);
        }
        await new Promise(r => setTimeout(r, 3000));

        if (followTimedOut) throw new Error("Follow timed out sau navigate profile");

        const pageTitle = await followPage.title();
        const currentUrl = followPage.url();
        console.log(`[Follow] Title: "${pageTitle}" | URL: ${currentUrl}`);

        if (!currentUrl.includes(`@${username}`)) {
          throw new Error(`Cookie không hợp lệ hoặc hết hạn — bị redirect về: ${currentUrl}`);
        }

        // FIX 2: Giảm timeout selector từ 15000 → 5000ms
        const SELECTORS = [
          'button[data-e2e="follow-button"]',
          'button[data-e2e="followButton"]',
          '[data-e2e="follow-button"]',
          '[data-e2e="followButton"]',
        ];

        let followButton = null;
        let usedSelector = null;

        for (const sel of SELECTORS) {
          if (followTimedOut) break;
          try {
            followButton = await followPage.waitForSelector(sel, { timeout: 5000 });
            if (followButton) { usedSelector = sel; break; }
          } catch (_) {}
        }

        // Fallback: scan toàn bộ button theo text
        if (!followButton && !followTimedOut) {
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
        if (!res.headersSent) {
          res.writeHead(500);
          res.end(JSON.stringify({ ok: false, error: e.message, message: "Lỗi server khi follow" }));
        }
      } finally {
        // FIX 4: Luôn clear timeout và đóng tab
        clearTimeout(followTimeoutHandle);
        if (followPage) {
          try { await followPage.close(); } catch (_) {}
          console.log(`[Follow] Tab đã đóng`);
        }
      }
      return;
    }

    // ========== ENDPOINT /follow-from-tool ==========
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

      try {
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

        if (!sessionid) {
          res.writeHead(400);
          res.end(JSON.stringify({ ok: false, error: "Không tìm thấy sessionid trong cookie" }));
          return;
        }

        // Bước 1: Lấy secUid qua API trực tiếp
        console.log(`[FollowTool] Lấy secUid của @${username} qua API...`);
        const userInfoUrl = `https://www.tiktok.com/api/user/detail/?uniqueId=${encodeURIComponent(username)}&aid=1988&app_name=tiktok_web&device_platform=web_pc&os=mac&region=VN&msToken=${msToken}`;

        const userInfoResult = await new Promise((resolve) => {
          const reqOptions = new URL(userInfoUrl);
          const options = {
            hostname: reqOptions.hostname,
            path: reqOptions.pathname + reqOptions.search,
            method: "GET",
            headers: {
              "Cookie": cookie,
              "User-Agent": DEFAULT_UA,
              "Referer": "https://www.tiktok.com/",
              "Accept": "application/json",
            },
          };
          const r = https.request(options, (resp) => {
            let data = "";
            resp.on("data", d => data += d);
            resp.on("end", () => {
              try { resolve({ ok: true, data: JSON.parse(data) }); }
              catch (e) { resolve({ ok: false, error: data.substring(0, 200) }); }
            });
          });
          r.on("error", e => resolve({ ok: false, error: e.message }));
          r.setTimeout(15000, () => { r.destroy(); resolve({ ok: false, error: "timeout" }); });
          r.end();
        });

        let secUid = null;
        if (userInfoResult.ok) {
          secUid = userInfoResult.data?.userInfo?.user?.secUid
            || userInfoResult.data?.user?.secUid
            || null;
        }

        if (!secUid) {
          console.log(`[FollowTool] Fallback lấy secUid qua browser...`);
          await initBrowser();
          await ensurePageReady();
          secUid = await page.evaluate(async (uname) => {
            try {
              const r = await fetch(`https://www.tiktok.com/api/user/detail/?uniqueId=${encodeURIComponent(uname)}&aid=1988&app_name=tiktok_web&device_platform=web_pc`, {
                credentials: "include"
              });
              const d = await r.json();
              return d?.userInfo?.user?.secUid || null;
            } catch (_) { return null; }
          }, username);
        }

        console.log(`[FollowTool] secUid: ${secUid ? secUid.substring(0, 30) + "..." : "không tìm thấy"}`);

        if (!secUid) {
          res.writeHead(500);
          res.end(JSON.stringify({ ok: false, error: `Không lấy được secUid của @${username}` }));
          return;
        }

        // Bước 2: Ký URL follow qua SDK
        const followParams = new URLSearchParams({
          secUid,
          action_type: "0",
          aid: "1988",
          app_name: "tiktok_web",
          browser_language: "vi-VN",
          browser_name: "Mozilla",
          browser_online: "true",
          browser_platform: "MacIntel",
          browser_version: "5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15",
          channel: "tiktok_web",
          cookie_enabled: "true",
          device_platform: "web_pc",
          focus_state: "true",
          from: "18",
          fromWeb: "1",
          from_page: "user",
          from_pre: "0",
          history_len: "5",
          is_fullscreen: "false",
          is_page_visible: "true",
          os: "mac",
          priority_region: "VN",
          referer: targetUrl,
          region: "VN",
          screen_height: "1080",
          screen_width: "1920",
          type: "1",
          tz_name: "Asia/Saigon",
          user_is_login: "true",
          verifyFp,
          webcast_language: "vi-VN",
          msToken,
        });

        const unsignedUrl = `https://www.tiktok.com/api/commit/follow/user/?${followParams.toString()}`;
        console.log(`[FollowTool] Ký URL follow...`);

        await initBrowser();
        await ensurePageReady();

        const cookieArray = [];
        for (const [name, value] of Object.entries(cookieObj)) {
          cookieArray.push({ name, value, domain: ".tiktok.com", path: "/" });
        }
        try { await page.setCookie(...cookieArray); } catch (_) {}

        const signResult = await generateSignedUrl(unsignedUrl);
        const signedUrl = signResult.signedUrl;
        console.log(`[FollowTool] URL đã ký, gọi API...`);

        // Bước 3: Gọi API follow qua HTTPS
        const followResult = await new Promise((resolve) => {
          const reqUrl = new URL(signedUrl);
          const options = {
            hostname: reqUrl.hostname,
            path: reqUrl.pathname + reqUrl.search,
            method: "POST",
            headers: {
              "Cookie": cookie,
              "User-Agent": DEFAULT_UA,
              "Referer": targetUrl,
              "Origin": "https://www.tiktok.com",
              "Accept": "application/json, text/plain, */*",
              "Content-Type": "application/x-www-form-urlencoded",
              "Content-Length": "0",
              "X-CSRFToken": csrfToken,
            },
          };
          const r = https.request(options, (resp) => {
            let data = "";
            resp.on("data", d => data += d);
            resp.on("end", () => {
              try { resolve({ status: resp.statusCode, data: JSON.parse(data), raw: data.substring(0, 300) }); }
              catch (e) { resolve({ status: resp.statusCode, raw: data.substring(0, 300), data: null }); }
            });
          });
          r.on("error", e => resolve({ error: e.message }));
          r.setTimeout(20000, () => { r.destroy(); resolve({ error: "timeout" }); });
          r.end();
        });

        console.log(`[FollowTool] Result: ${JSON.stringify(followResult).substring(0, 300)}`);

        const tiktokCode = followResult.data?.status_code;
        const success = followResult.status === 200 && (tiktokCode === 0 || tiktokCode === undefined);

        res.writeHead(200);
        res.end(JSON.stringify({
          ok: success,
          status_code: followResult.status,
          tiktok_status_code: tiktokCode,
          target_username: username,
          target_url: targetUrl,
          data: followResult.data,
          raw: followResult.raw,
          message: success
            ? `Follow @${username} thành công`
            : followResult.error
              ? `Lỗi: ${followResult.error}`
              : `TikTok từ chối: status_code=${tiktokCode}`
        }));

      } catch (e) {
        console.error("[FollowTool] Lỗi:", e.message);
        res.writeHead(500);
        res.end(JSON.stringify({ ok: false, error: e.message, message: "Lỗi server" }));
      }
      return;
    }

    // ── /follow-mobile ──
    if (url.pathname === '/follow-mobile' && req.method === 'POST') {
      let body = '';
      for await (const chunk of req) body += chunk;

      let cookie, username, targetUrl;
      try {
        const json = JSON.parse(body);
        cookie = json.cookie;
        username = json.username;
        targetUrl = json.target_url;
        if (targetUrl && !username) {
          const match = targetUrl.match(/@([^/?&]+)/);
          if (match) username = match[1];
        }
      } catch (e) {
        res.writeHead(400);
        res.end(JSON.stringify({ ok: false, error: 'Invalid JSON' }));
        return;
      }

      if (!cookie || !username) {
        res.writeHead(400);
        res.end(JSON.stringify({ ok: false, error: 'Thiếu cookie hoặc username' }));
        return;
      }

      try {
        console.log(`[FollowMobile] Đang follow @${username}...`);

        const { spawn } = await import('child_process');
        const python = spawn('python3', ['mobile_signer.py'], {
          cwd: process.cwd(),
          stdio: ['pipe', 'pipe', 'pipe']
        });

        const inputData = JSON.stringify({
          query: '',
          ts: Math.floor(Date.now() / 1000),
          device_id: '7629627162782778888',
          cookie: cookie
        });

        let output = '';
        let errorOut = '';

        python.stdout.on('data', (data) => output += data.toString());
        python.stderr.on('data', (data) => errorOut += data.toString());

        python.on('close', async (code) => {
          if (code !== 0) {
            res.writeHead(500);
            res.end(JSON.stringify({ ok: false, error: `Python signer lỗi: ${errorOut}` }));
            return;
          }

          try {
            const signResult = JSON.parse(output);
            console.log('[FollowMobile] Chữ ký:', JSON.stringify(signResult).slice(0, 200));

            res.writeHead(200);
            res.end(JSON.stringify({
              ok: true,
              message: `Đã tạo chữ ký cho @${username}`,
              signatures: signResult
            }));
          } catch (e) {
            res.writeHead(500);
            res.end(JSON.stringify({ ok: false, error: `Lỗi parse JSON từ Python: ${output}` }));
          }
        });

        python.on('error', (err) => {
          res.writeHead(500);
          res.end(JSON.stringify({ ok: false, error: `Không thể chạy Python: ${err.message}` }));
        });

        python.stdin.write(inputData);
        python.stdin.end();

      } catch (e) {
        res.writeHead(500);
        res.end(JSON.stringify({ ok: false, error: e.message }));
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
  console.log(`  POST /signature        - Generate signed URL`);
  console.log(`  POST /fetch            - Fetch through browser`);
  console.log(`  GET  /health           - Health check`);
  console.log(`  GET  /restart          - Restart browser session`);
  console.log(`  POST /follow           - Follow qua browser (đã fix)`);
  console.log(`  POST /follow-from-tool - Follow từ tool ngoài`);
  console.log(`  POST /follow-mobile    - Follow via Mobile API`);

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
