#!/usr/bin/env node
/**
 * TikTok Signature Server (gọn)
 *
 * Endpoints:
 * - GET  /health       - Health check
 * - GET  /restart      - Restart browser
 * - POST /signature    - Ký bất kỳ URL nào
 * - POST /sign-follow  - Ký URL follow, trả về để iPhone tự gọi TikTok
 *
 * Env:
 * - PORT
 * - PROXY_ENABLED / PROXY_HOST / PROXY_USER / PROXY_PASS
 */

import http from "http";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import puppeteer from "puppeteer-extra";
import StealthPlugin from "puppeteer-extra-plugin-stealth";
import { encode as encodeXGnarly } from "./xgnarly.mjs";

puppeteer.use(StealthPlugin());

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8080;
const USER_DATA_DIR = path.join(__dirname, ".chrome-profile");
const DEFAULT_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15";

// Proxy
const PROXY_ENABLED = process.env.PROXY_ENABLED === "true" && process.env.PROXY_HOST;
const PROXY_HOST = process.env.PROXY_HOST || "";
const PROXY_USER = process.env.PROXY_USER || "";
const PROXY_PASS = process.env.PROXY_PASS || "";

// SDK files
const SDK_PATH     = path.join(__dirname, "javascript", "webmssdk_5.1.3.js");
const SDK_368_PATH = path.join(__dirname, "javascript", "webmssdk_1.0.0.368.js");
const SDK_485_PATH = path.join(__dirname, "javascript", "webmssdk_2.0.0.485.js");

const loadFile = (p) => { try { return fs.existsSync(p) ? fs.readFileSync(p, "utf-8") : null; } catch { return null; } };
const localSdk = loadFile(SDK_PATH);
const sdk368   = loadFile(SDK_368_PATH);
const sdk485   = loadFile(SDK_485_PATH);
if (localSdk) console.log("[Server] SDK loaded:", SDK_PATH);

// Browser state
let browser = null, page = null, cookies = null;
let isReady = false, isInitializing = false;
let generationCount = 0, lastInitTime = null;

const MAX_GENS    = 500;
const MAX_AGE_MS  = 30 * 60 * 1000;

// Signed URL cache (keyed by pathname)
const urlCache = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of urlCache) if (now - v.at > 60_000) urlCache.delete(k);
}, 60_000);

// Request queue
const queue = [];
let processing = false;

function enqueue(fn) {
  return new Promise((res, rej) => {
    queue.push({ fn, res, rej });
    runQueue();
  });
}

async function runQueue() {
  if (processing || !queue.length) return;
  processing = true;
  while (queue.length) {
    const { fn, res, rej } = queue.shift();
    try { res(await fn()); } catch (e) { rej(e); }
  }
  processing = false;
}

// ── Browser init ──────────────────────────────────────────────
async function initBrowser() {
  if (isInitializing) { while (isInitializing) await sleep(100); return; }
  if (isReady && browser && page) return;
  isInitializing = true;
  console.log("[Server] Initializing browser...");

  try {
    const chromePath = (() => {
      if (process.env.PUPPETEER_EXECUTABLE_PATH) return process.env.PUPPETEER_EXECUTABLE_PATH;
      if (process.platform === "darwin") return "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
      for (const p of ["/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable"]) {
        try { fs.accessSync(p); return p; } catch {}
      }
    })();

    const args = [
      "--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage",
      "--disable-blink-features=AutomationControlled", "--disable-gpu", "--window-size=1920,1080",
    ];
    if (PROXY_ENABLED) { args.push(`--proxy-server=http://${PROXY_HOST}`); console.log("[Server] Proxy:", PROXY_HOST); }

    if (!fs.existsSync(USER_DATA_DIR)) fs.mkdirSync(USER_DATA_DIR, { recursive: true });

    browser = await puppeteer.launch({
      headless: "new", executablePath: chromePath,
      args, userDataDir: USER_DATA_DIR,
      ignoreDefaultArgs: ["--enable-automation"],
    });

    page = await browser.newPage();

    // Cache signed URLs emitted by the page
    page.on("request", (req) => {
      try {
        const u = req.url();
        if (!u.includes("X-Gnarly=")) return;
        const parsed = new URL(u);
        urlCache.set(parsed.pathname, { url: u, at: Date.now() });
      } catch {}
    });

    if (PROXY_ENABLED && PROXY_USER) await page.authenticate({ username: PROXY_USER, password: PROXY_PASS });

    await page.setUserAgent(DEFAULT_UA);
    await page.setViewport({ width: 1920, height: 1080 });
    await page.evaluateOnNewDocument(() => {
      Object.defineProperty(navigator, "platform", { get: () => "MacIntel", configurable: true });
      if (!window.process) window.process = { env: { NODE_ENV: "production" }, browser: true, version: "", versions: {} };
    });

    // Inject local SDK before page load
    if (!localSdk) throw new Error("webmssdk_5.1.3.js not found in javascript/");
    await page.evaluateOnNewDocument((code) => { try { eval(code); } catch (e) { console.error("[SDK]", e.message); } }, localSdk);

    // Intercept requests: serve local SDK files, block heavy assets
    await page.setRequestInterception(true);
    page.on("request", async (req) => {
      const u = req.url(), rt = req.resourceType();
      if (u.includes("/webmssdk/")) {
        const body = u.includes("2.0.0.485") ? sdk485 : u.includes("1.0.0.368") ? sdk368 : sdk485;
        if (body) { try { await req.respond({ status: 200, contentType: "application/javascript; charset=utf-8", body }); } catch { await req.abort(); } return; }
      }
      if (u.includes("slardar") || u.includes("acrawler")) { await req.abort(); return; }
      if (["image", "media", "font"].includes(rt)) { await req.abort(); return; }
      await req.continue();
    });

    console.log("[Server] Navigating to TikTok...");
    await page.goto("https://www.tiktok.com/@zara", { waitUntil: "domcontentloaded", timeout: 60000 });
    await sleep(3000);

    // Verify SDK loaded
    const sdk = await page.evaluate(() => ({
      ok: !!(window.byted_acrawler?.frontierSign),
    }));
    if (!sdk.ok) throw new Error("SDK failed to initialize");
    console.log("[Server] SDK ready");

    // Warm up + reload to stabilize
    await page.evaluate(() => window.scrollBy(0, 500));
    await sleep(2000);
    try { await page.reload({ waitUntil: "domcontentloaded", timeout: 60000 }); } catch {}
    await sleep(3000);
    await dismissError();

    cookies = await page.cookies();
    lastInitTime = new Date().toISOString();
    isReady = true;
    console.log(`[Server] Ready — ${cookies.length} cookies`);
  } catch (e) {
    console.error("[Server] Init error:", e.message);
    await closeBrowser();
    throw e;
  } finally {
    isInitializing = false;
  }
}

async function dismissError() {
  try {
    const hasError = await page.evaluate(() => /Something went wrong/i.test(document.body?.innerText || ""));
    if (!hasError) return;
    console.log("[Server] Dismissing error page...");
    await page.evaluate(() => {
      const btn = [...document.querySelectorAll("button")].find(b => /Refresh/i.test(b.textContent));
      if (btn) btn.click();
    });
    try { await page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 30000 }); } catch {}
    await sleep(3000);
  } catch {}
}

async function closeBrowser() {
  isReady = false; cookies = null; generationCount = 0; lastInitTime = null;
  try { await browser?.close(); } catch {}
  browser = null; page = null;
  try { if (fs.existsSync(USER_DATA_DIR)) fs.rmSync(USER_DATA_DIR, { recursive: true, force: true }); } catch {}
  console.log("[Server] Browser closed");
}

async function ensureReady() {
  if (!browser || !page) { isReady = false; await initBrowser(); return; }
  const age = Date.now() - new Date(lastInitTime).getTime();
  if (generationCount >= MAX_GENS || age >= MAX_AGE_MS) {
    console.log("[Server] Session refresh...");
    await closeBrowser(); await initBrowser();
  }
}

// ── Signing ───────────────────────────────────────────────────
async function signUrl(targetUrl) {
  return enqueue(async () => {
    await initBrowser();
    await ensureReady();

    const u = new URL(targetUrl);
    u.searchParams.delete("X-Bogus");
    u.searchParams.delete("X-Gnarly");
    u.searchParams.delete("msToken");
    normalizeFingerprint(u);

    const out = await page.evaluate((url) => {
      if (!window.__sdkN) return { error: "SDK not initialized" };
      const sdkN = window.__sdkN;
      const table = sdkN.u?.[995]?.v ? sdkN.u : sdkN.B?.o?.[995]?.v ? sdkN.B.o : sdkN.o?.[995]?.v ? sdkN.o : null;
      if (!table) return { error: "SDK table not found" };
      const fn = table[995]?.v;
      if (typeof fn !== "function") return { error: "SDK fn not found" };

      const uu = new URL(url);
      const msToken = (document.cookie.match(/msToken=([^;]+)/g) || []).at(-1)?.split("=", 2)[1] || "";
      uu.searchParams.set("msToken", msToken);
      const qs = uu.search.slice(1);

      if (!window.__sigN) window.__sigN = 100;
      window.__sigN++;
      const n = window.__sigN;
      let counters = {
        totalXHRRequests: Math.floor(n * 0.6),
        totalFetchRequests: Math.floor(n * 0.4) + 3,
        interceptedXHRRequests: Math.floor(n * 0.1),
        interceptedFetchRequests: Math.floor(n * 0.05) + 1,
      };
      try {
        const last = [...(window.__cap3 || [])].reverse().find(c => c.fn === "gnarly_x" && c.args?.[3]?.v);
        if (last) {
          const v = last.args[3].v;
          const c2 = {
            totalXHRRequests: v.totalXHRRequests?.v || 0,
            totalFetchRequests: v.totalFetchRequests?.v || 0,
            interceptedXHRRequests: v.interceptedXHRRequests?.v || 0,
            interceptedFetchRequests: v.interceptedFetchRequests?.v || 0,
          };
          if (c2.totalXHRRequests + c2.totalFetchRequests > 0) counters = c2;
        }
      } catch {}

      try {
        const xb = fn.call(window.byted_acrawler || null, qs, "");
        return { urlBase: uu.toString(), qs, xBogus: xb, msToken, ua: navigator.userAgent, counters };
      } catch (e) { return { error: e.message }; }
    }, u.toString());

    if (out.error) throw new Error("Sign failed: " + out.error);

    const xg = encodeXGnarly(out.qs, "", out.ua, out.counters, { ubcode: 4, sdkVersion: "1.0.0.368" });
    const signed = new URL(out.urlBase);
    signed.searchParams.set("X-Bogus", out.xBogus);
    signed.searchParams.set("X-Gnarly", xg);

    cookies = await page.cookies();
    generationCount++;

    return {
      signedUrl: signed.toString(),
      xBogus: out.xBogus,
      xGnarly: xg,
      cookies: cookies.map(c => `${c.name}=${c.value}`).join("; "),
      userAgent: DEFAULT_UA,
    };
  });
}

function normalizeFingerprint(urlObj) {
  const map = { browser_platform: "MacIntel", os: "mac", screen_width: "1920", screen_height: "1080" };
  for (const [k, v] of Object.entries(map)) if (urlObj.searchParams.has(k)) urlObj.searchParams.set(k, v);
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ── HTTP Server ───────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Content-Type", "application/json");

  if (req.method === "OPTIONS") { res.writeHead(200); res.end(); return; }

  const json = (code, data) => { res.writeHead(code); res.end(JSON.stringify(data)); };

  // Đọc body
  const body = await new Promise(r => { let s = ""; req.on("data", c => s += c); req.on("end", () => r(s)); });
  let parsed = {};
  try { parsed = JSON.parse(body); } catch {}

  try {
    // ── GET /health ──
    if (url.pathname === "/health" && req.method === "GET") {
      if (!isReady && !isInitializing) initBrowser().catch(() => {});
      const age = lastInitTime ? Date.now() - new Date(lastInitTime).getTime() : 0;
      return json(200, {
        status: "ok", ready: isReady, initializing: isInitializing,
        sessionAgeMinutes: Math.round(age / 60000),
        generationCount, queueLength: queue.length,
        sdkLoaded: !!localSdk,
      });
    }

    // ── GET /restart ──
    if (url.pathname === "/restart" && req.method === "GET") {
      await closeBrowser();
      await initBrowser();
      return json(200, { status: "ok", message: "Browser restarted" });
    }

    // ── POST /signature ──
    // Ký bất kỳ URL nào, trả về signed URL
    if (url.pathname === "/signature" && req.method === "POST") {
      const targetUrl = parsed.url || body.trim();
      if (!targetUrl) return json(400, { error: "url is required" });

      const result = await signUrl(targetUrl);
      return json(200, {
        status: "ok",
        data: {
          signed_url: result.signedUrl,
          "x-bogus": result.xBogus,
          "x-gnarly": result.xGnarly,
          cookies: result.cookies,
          navigator: { user_agent: result.userAgent, platform: "MacIntel", browser_language: "en-US", os: "mac", screen_width: "1920", screen_height: "1080" },
        },
      });
    }

    // ── POST /sign-follow ──
    // Nhận username + cookie, trả về signed URL để iPhone tự gọi TikTok
    // iPhone nhận về rồi POST signed_url với cookie đó là follow xong
    if (url.pathname === "/sign-follow" && req.method === "POST") {
      const { username, cookie, secUid: secUidInput } = parsed;
      if (!username || !cookie) return json(400, { error: "username và cookie là bắt buộc" });

      // Parse cookie
      const cookieObj = Object.fromEntries(
        cookie.split(";").map(p => p.trim()).filter(p => p.includes("="))
          .map(p => { const i = p.indexOf("="); return [p.slice(0, i).trim(), p.slice(i + 1).trim()]; })
      );
      const msToken  = (cookie.match(/msToken=([^;]+)/g) || []).at(-1)?.split("=").slice(1).join("=") || "";
      const verifyFp = cookieObj["s_v_web_id"] || "";
      const csrfToken = cookieObj["tt_csrf_token"] || "";

      if (!cookieObj["sessionid"]) return json(400, { error: "Không tìm thấy sessionid trong cookie" });

      // Dùng secUid từ client nếu có, không thì báo lỗi luôn (tránh gọi TikTok API từ server)
      // Client nên tự lấy secUid hoặc cache lại
      let secUid = secUidInput || null;

      if (!secUid) {
        // Thử lấy qua SDK browser (không gọi TikTok API trực tiếp từ server)
        await initBrowser();
        await ensureReady();
        secUid = await page.evaluate(async (uname) => {
          try {
            const r = await fetch(`/api/user/detail/?uniqueId=${encodeURIComponent(uname)}&aid=1988&app_name=tiktok_web&device_platform=web_pc`, { credentials: "include" });
            const d = await r.json();
            return d?.userInfo?.user?.secUid || null;
          } catch { return null; }
        }, username);
      }

      if (!secUid) return json(500, { error: `Không lấy được secUid của @${username}. Truyền secUid trực tiếp vào request để bỏ qua bước này.` });

      // Build URL follow chưa ký
      const params = new URLSearchParams({
        secUid, action_type: "0", aid: "1988", app_name: "tiktok_web",
        browser_language: "vi-VN", browser_name: "Mozilla", browser_online: "true",
        browser_platform: "MacIntel",
        browser_version: "5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15",
        channel: "tiktok_web", cookie_enabled: "true", device_platform: "web_pc",
        focus_state: "true", from: "18", fromWeb: "1", from_page: "user",
        from_pre: "0", history_len: "5", is_fullscreen: "false", is_page_visible: "true",
        os: "mac", priority_region: "VN", region: "VN",
        referer: `https://www.tiktok.com/@${username}`,
        screen_height: "1080", screen_width: "1920", type: "1",
        tz_name: "Asia/Saigon", user_is_login: "true",
        verifyFp, webcast_language: "vi-VN", msToken,
      });

      const unsignedUrl = `https://www.tiktok.com/api/commit/follow/user/?${params}`;
      const result = await signUrl(unsignedUrl);

      // Trả về mọi thứ iPhone cần để tự gọi TikTok
      return json(200, {
        status: "ok",
        data: {
          signed_url: result.signedUrl,   // iPhone POST cái này
          cookie,                          // iPhone gửi kèm header Cookie
          csrf_token: csrfToken,           // iPhone gửi kèm header X-CSRFToken
          user_agent: DEFAULT_UA,          // iPhone gửi kèm header User-Agent
          referer: `https://www.tiktok.com/@${username}`,
          username,
          secUid,                          // Cache lại để dùng lần sau
        },
      });
    }

    json(404, { error: "Not found" });
  } catch (e) {
    console.error("[Server] Error:", e.message);
    json(500, { error: e.message });
  }
});

server.listen(PORT, () => {
  console.log(`[Server] Running on port ${PORT}`);
  console.log(`  GET  /health      - Health check`);
  console.log(`  GET  /restart     - Restart browser`);
  console.log(`  POST /signature   - Ký URL bất kỳ`);
  console.log(`  POST /sign-follow - Ký URL follow, iPhone tự gọi TikTok`);
  initBrowser().catch(e => console.error("[Server] Init failed:", e.message));
});

process.on("SIGINT",  async () => { await closeBrowser(); process.exit(0); });
process.on("SIGTERM", async () => { await closeBrowser(); process.exit(0); });
