require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const dns = require("node:dns").promises;
const net = require("node:net");
const https = require("node:https");
const path = require("node:path");
const crypto = require("node:crypto");
const { Readable, Transform } = require("node:stream");
const { pipeline } = require("node:stream/promises");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const API_KEY = process.env.API_KEY || "";
const YOUTUBE_API_KEY = process.env.YOUTUBE_API_KEY || "";
// Each YouTube search costs 100 quota units; the default daily quota is 10,000 (~100 searches).
const YOUTUBE_DAILY_LIMIT = Math.max(1, Number(process.env.YOUTUBE_DAILY_LIMIT || 90));
const CACHE_TTL_MS = Math.max(0, Number(process.env.SEARCH_CACHE_MINUTES || 30)) * 60_000;
const searchCache = new Map();
let quotaDay = new Date().toISOString().slice(0, 10);
let quotaUsed = 0;
const MAX_BYTES = Math.max(1, Number(process.env.MAX_DOWNLOAD_MB || 25)) * 1024 * 1024;
const TIMEOUT_MS = Math.max(5, Number(process.env.SOURCE_TIMEOUT_SECONDS || 30)) * 1000;
const ALLOWED_HOSTS = (process.env.ALLOWED_HOSTS || "")
  .split(",").map(host => host.trim().toLowerCase()).filter(Boolean);

app.disable("x-powered-by");
// Required behind Render/Heroku/etc. so rate limiting sees the real client IP.
app.set("trust proxy", Number(process.env.TRUST_PROXY_HOPS || 1));
app.use(helmet());
app.use(express.json({ limit: "12kb", strict: true }));
app.use(rateLimit({
  windowMs: 60_000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  skip: req => req.path === "/" || req.path === "/api/health",
  message: { success: false, error: "Too many requests. Please try again in a minute." }
}));

app.get("/", (_req, res) => res.json({
  success: true,
  name: "EMMYFROSH MUSIC API",
  version: "3.1.0",
  creator: "EMMYFROSH",
  description: "YouTube music search plus authorized direct MP3 downloads.",
  endpoints: {
    health: "GET /api/health",
    downloadGet: "GET /api/download?url=<direct-mp3-url>",
    downloadPost: "POST /api/download with JSON body { url: ... }",
    search: "GET /api/search?q=<search terms>",
    providers: "GET /api/providers"
  },
  authentication: "Send your API key in the x-api-key header."
}));

app.get("/api/health", (_req, res) => res.json({
  success: true,
  status: "online",
  name: "EMMYFROSH MUSIC API",
  version: "3.1.0",
  creator: "EMMYFROSH"
}));

function requireApiKey(req, res, next) {
  if (!API_KEY || API_KEY === "replace-this-with-a-long-random-secret") {
    return res.status(503).json({ success: false, error: "Server API_KEY is not configured." });
  }
  const supplied = Buffer.from(req.get("x-api-key") || "");
  const expected = Buffer.from(API_KEY);
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    return res.status(401).json({ success: false, error: "Invalid or missing API key. Send it in the x-api-key header." });
  }
  next();
}

function isPublicIPv4(address) {
  if (net.isIP(address) !== 4) return false;
  const [a, b] = address.split(".").map(Number);
  // Reject private, loopback, link-local, carrier-grade NAT, documentation,
  // benchmarking, multicast, reserved and other non-public IPv4 ranges.
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  const [, , c] = address.split(".").map(Number);
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
  if (a === 192 && b === 88 && c === 99) return false;
  if (a === 192 && b === 168) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

async function validateSourceUrl(rawUrl) {
  let url;
  try { url = new URL(rawUrl); } catch { throw new Error("The url value is not a valid URL."); }
  if (url.protocol !== "https:") throw new Error("Only HTTPS direct audio links are accepted.");
  if (url.username || url.password) throw new Error("URLs containing login credentials are not accepted.");
  if (url.port && url.port !== "443") throw new Error("Only the standard HTTPS port (443) is accepted.");
  if (url.hash) url.hash = "";
  const hostname = url.hostname.toLowerCase();
  if (!hostname || hostname === "localhost" || hostname.endsWith(".localhost")) {
    throw new Error("Local or invalid hostnames are not accepted.");
  }
  if (ALLOWED_HOSTS.length && !ALLOWED_HOSTS.includes(hostname)) {
    throw new Error("This source host is not on the server's ALLOWED_HOSTS list.");
  }

  const records = await dns.lookup(hostname, { all: true, verbatim: true, family: 4 });
  if (!records.length || records.some(record => !isPublicIPv4(record.address))) {
    throw new Error("The source host must resolve only to public IPv4 addresses.");
  }
  // Pin the request to an already-validated IP to prevent DNS-rebinding SSRF.
  return { url, ip: records[0].address };
}

function pinnedLookup(ip) {
  return (_hostname, options, callback) => {
    if (options && options.all) return callback(null, [{ address: ip, family: 4 }]);
    callback(null, ip, 4);
  };
}

function getRequestUrl(req) {
  const candidate = req.method === "POST" ? req.body?.url : req.query.url;
  if (typeof candidate !== "string" || !candidate.trim()) {
    throw new Error("Provide a direct MP3 file URL in the url field.");
  }
  if (candidate.length > 4096) throw new Error("The audio URL is too long.");
  return candidate.trim();
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(TIMEOUT_MS) });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = data?.error?.message || data?.error?.description || `Provider returned HTTP ${response.status}.`;
    throw new Error(message);
  }
  return data;
}

function decodeEntities(text) {
  return String(text || "")
    .replace(/&#(\d+);/g, (_m, n) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_m, n) => String.fromCodePoint(parseInt(n, 16)))
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

function takeQuota() {
  const today = new Date().toISOString().slice(0, 10);
  if (today !== quotaDay) { quotaDay = today; quotaUsed = 0; }
  if (quotaUsed >= YOUTUBE_DAILY_LIMIT) {
    throw new Error("Daily YouTube search limit reached on this server. Try again tomorrow.");
  }
  quotaUsed += 1;
}

async function searchYouTube(query) {
  if (!YOUTUBE_API_KEY) throw new Error("YouTube search is not configured on this server.");
  const cacheKey = query.toLowerCase();
  const cached = searchCache.get(cacheKey);
  if (cached && Date.now() - cached.at < CACHE_TTL_MS) return cached.items;

  takeQuota();
  const endpoint = new URL("https://www.googleapis.com/youtube/v3/search");
  endpoint.search = new URLSearchParams({
    part: "snippet", type: "video", maxResults: "10", q: query, key: YOUTUBE_API_KEY
  }).toString();
  const data = await fetchJson(endpoint);
  const items = (data.items || []).filter(item => item.id?.videoId).map(item => ({
    source: "youtube",
    id: item.id.videoId,
    title: decodeEntities(item.snippet?.title) || "Untitled",
    artist: decodeEntities(item.snippet?.channelTitle),
    description: decodeEntities(item.snippet?.description),
    thumbnail: item.snippet?.thumbnails?.high?.url || item.snippet?.thumbnails?.default?.url || null,
    url: `https://www.youtube.com/watch?v=${item.id.videoId}`,
    downloadable: false,
    note: "YouTube result link only. Use YouTube's official options or an authorized download source."
  }));
  if (CACHE_TTL_MS > 0) {
    if (searchCache.size >= 500) searchCache.delete(searchCache.keys().next().value);
    searchCache.set(cacheKey, { at: Date.now(), items });
  }
  return items;
}

async function searchHandler(req, res) {
  const query = typeof req.query.q === "string" ? req.query.q.trim() : "";
  const source = typeof req.query.source === "string" ? req.query.source.toLowerCase() : "youtube";
  if (!query || query.length > 150) return res.status(400).json({ success: false, error: "Provide q with 1–150 characters of search text." });
  if (!["youtube", "all"].includes(source)) return res.status(400).json({ success: false, error: "Only source=youtube is supported." });
  try {
    const results = await searchYouTube(query);
    return res.json({ success: true, creator: "EMMYFROSH", query, results, count: results.length,
      downloadInfo: "Search results are YouTube links, not downloadable files. Use /api/download only with a direct MP3 URL you are authorized to download." });
  } catch (error) {
    const limited = /limit reached/.test(error.message);
    const notConfigured = /not configured/.test(error.message);
    return res.status(limited ? 429 : notConfigured ? 503 : 502).json({ success: false, error: error.message || "YouTube search failed." });
  }
}

function makeFilename(sourceUrl) {
  let base = path.basename(sourceUrl.pathname || "music.mp3");
  try { base = decodeURIComponent(base); } catch { /* keep encoded filename */ }
  base = base.replace(/\.mp3$/i, "").replace(/[^a-zA-Z0-9._-]/g, "_").replace(/^\.+/, "").slice(0, 90);
  return `${base || "emmyfrosh-music"}.mp3`;
}

function requestSource(url, ip) {
  return new Promise((resolve, reject) => {
    const request = https.request({
      protocol: "https:",
      hostname: url.hostname,
      port: 443,
      path: `${url.pathname}${url.search}`,
      method: "GET",
      headers: { Accept: "audio/mpeg, application/octet-stream;q=0.8", "User-Agent": "EMMYFROSH-MUSIC-API/3.1" },
      servername: url.hostname,
      rejectUnauthorized: true,
      family: 4,
      lookup: pinnedLookup(ip),
      agent: false
    }, resolve);
    request.setTimeout(TIMEOUT_MS, () => request.destroy(new Error("The audio source timed out.")));
    request.on("error", reject);
    request.end();
  });
}

function looksLikeMp3(buffer) {
  if (!buffer || buffer.length < 2) return false;
  if (buffer.length >= 3 && buffer.subarray(0, 3).toString("ascii") === "ID3") return true;
  return buffer[0] === 0xff && (buffer[1] & 0xe0) === 0xe0;
}

async function downloadHandler(req, res) {
  let source;
  try {
    source = await validateSourceUrl(getRequestUrl(req));
  } catch (error) {
    return res.status(400).json({ success: false, error: error.message });
  }

  let upstream;
  try {
    upstream = await requestSource(source.url, source.ip);
    if (upstream.statusCode >= 300 && upstream.statusCode < 400) {
      upstream.resume();
      return res.status(400).json({ success: false, error: "Redirects are not followed. Use the final direct HTTPS MP3 URL." });
    }
    if (upstream.statusCode !== 200) {
      const status = upstream.statusCode || 502;
      upstream.resume();
      return res.status(502).json({ success: false, error: `Audio source returned HTTP ${status}.` });
    }

    const contentType = (upstream.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
    const isMp3Type = contentType === "audio/mpeg" || contentType === "audio/mp3" ||
      (contentType === "application/octet-stream" && source.url.pathname.toLowerCase().endsWith(".mp3"));
    if (!isMp3Type) {
      upstream.destroy();
      return res.status(415).json({ success: false, error: "The URL must return an MP3 file (audio/mpeg or an .mp3 octet-stream)." });
    }

    const declaredSize = Number(upstream.headers["content-length"] || 0);
    if (declaredSize > MAX_BYTES) {
      upstream.destroy();
      return res.status(413).json({ success: false, error: `MP3 exceeds the ${Math.floor(MAX_BYTES / 1024 / 1024)} MB file-size limit.` });
    }

    // Absolute cap on total transfer time (the socket timeout only catches idle connections).
    const deadline = setTimeout(() => upstream.destroy(new Error("The audio source timed out.")), TIMEOUT_MS * 4);
    deadline.unref();
    const clear = () => clearTimeout(deadline);
    res.on("close", clear);
    const iterator = upstream[Symbol.asyncIterator]();
    const prefix = [];
    let prefixLength = 0;
    while (prefixLength < 3) {
      const part = await iterator.next();
      if (part.done) break;
      prefix.push(Buffer.from(part.value));
      prefixLength += part.value.length;
    }
    const firstBytes = Buffer.concat(prefix, prefixLength);
    if (!looksLikeMp3(firstBytes)) {
      upstream.destroy();
      return res.status(415).json({ success: false, error: "The response does not appear to contain valid MP3 audio." });
    }

    const filename = makeFilename(source.url);
    res.status(200);
    res.set({
      "Content-Type": "audio/mpeg",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Accept-Ranges": "none"
    });
    if (declaredSize > 0) res.set("Content-Length", String(declaredSize));

    let received = 0;
    const sizeGuard = new Transform({
      transform(chunk, _encoding, callback) {
        received += chunk.length;
        if (received > MAX_BYTES) return callback(new Error("MP3 exceeds the configured file-size limit."));
        callback(null, chunk);
      }
    });
    const sourceStream = Readable.from((async function* () {
      yield firstBytes;
      while (true) {
        const part = await iterator.next();
        if (part.done) break;
        yield part.value;
      }
    })());

    res.on("close", () => {
      if (!res.writableEnded) upstream.destroy();
    });
    await pipeline(sourceStream, sizeGuard, res);
  } catch (error) {
    if (upstream && !upstream.destroyed) upstream.destroy();
    if (!res.headersSent) {
      const tooLarge = /file-size limit/.test(error.message || "");
      const timeout = /timed out/.test(error.message || "");
      res.status(tooLarge ? 413 : timeout ? 504 : 502).json({
        success: false,
        error: tooLarge ? `MP3 exceeds the ${Math.floor(MAX_BYTES / 1024 / 1024)} MB file-size limit.` :
          timeout ? "The audio source timed out." : "Could not download the MP3 from that source."
      });
    } else if (!res.destroyed) {
      res.destroy(error);
    }
  }
}

app.get("/api/providers", (_req, res) => res.json({
  success: true,
  creator: "EMMYFROSH",
  providers: {
    youtube: { search: Boolean(YOUTUBE_API_KEY), catalog: true, mp3Download: false },
    directMp3: { enabled: true, mp3Download: true, authorizationRequired: true }
  }
}));
app.get("/api/search", requireApiKey, searchHandler);

app.get("/api/download", requireApiKey, downloadHandler);
app.post("/api/download", requireApiKey, downloadHandler);

app.use((_req, res) => res.status(404).json({ success: false, error: "Endpoint not found." }));
app.use((error, _req, res, _next) => {
  if (error instanceof SyntaxError && "body" in error) {
    return res.status(400).json({ success: false, error: "Invalid JSON request body." });
  }
  console.error(error);
  if (!res.headersSent) res.status(500).json({ success: false, error: "Internal server error." });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`EMMYFROSH MUSIC API v3.1.0 listening on port ${PORT}`);
});
