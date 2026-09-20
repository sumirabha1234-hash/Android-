import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = 3000;

// Allow large payloads up to 2GB
app.use(express.json({ limit: "2048mb" }));
app.use(express.urlencoded({ extended: true, limit: "2048mb" }));

// API Routes
app.get("/api/health", (_req, res) => {
  res.json({
    status: "ok",
    maxUploadLimit: "2GB",
    timestamp: Date.now(),
  });
});

// Probe remote URL for metadata (file name, content-length, type)
app.post("/api/probe-url", async (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "Missing or invalid 'url' parameter" });
  }

  try {
    const parsedUrl = new URL(url);
    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      return res.status(400).json({ error: "Only HTTP and HTTPS protocols are supported" });
    }

    // Try HEAD request first, fallback to GET with range 0-0
    let response = await fetch(url, {
      method: "HEAD",
      headers: {
        "User-Agent": "APKGuard-SecurityAnalyzer/2.0 (compatible; Android Decompiler)",
      },
      redirect: "follow",
    });

    if (!response.ok) {
      // Retry with GET if HEAD not allowed
      response = await fetch(url, {
        method: "GET",
        headers: {
          "User-Agent": "APKGuard-SecurityAnalyzer/2.0 (compatible; Android Decompiler)",
          Range: "bytes=0-1024",
        },
        redirect: "follow",
      });
    }

    const contentLength = response.headers.get("content-length");
    const contentType = response.headers.get("content-type") || "application/octet-stream";
    const contentDisposition = response.headers.get("content-disposition");

    // Extract filename from Content-Disposition or URL path
    let fileName = "";
    if (contentDisposition) {
      const match = contentDisposition.match(/filename\*?=(?:UTF-8'')?["']?([^"';]+)["']?/i);
      if (match && match[1]) {
        fileName = decodeURIComponent(match[1].trim());
      }
    }

    if (!fileName) {
      const pathSegments = parsedUrl.pathname.split("/").filter(Boolean);
      fileName = pathSegments[pathSegments.length - 1] || "downloaded-binary.apk";
      if (!fileName.includes(".")) {
        fileName += ".apk";
      }
    }

    const sizeBytes = contentLength ? parseInt(contentLength, 10) : 0;
    const maxSizeBytes = 2 * 1024 * 1024 * 1024; // 2GB

    if (sizeBytes > maxSizeBytes) {
      return res.status(413).json({
        error: `File size exceeds the 2.0 GB limit (${(sizeBytes / (1024 * 1024 * 1024)).toFixed(2)} GB)`,
        sizeBytes,
        fileName,
      });
    }

    res.json({
      success: true,
      url,
      fileName,
      sizeBytes,
      contentType,
      acceptRanges: response.headers.get("accept-ranges") === "bytes",
    });
  } catch (err: any) {
    res.status(500).json({
      error: `Failed to probe remote link: ${err.message || "Unknown error"}`,
    });
  }
});

// Proxy download remote file (handles CORS, redirects, and streams back binary)
app.post("/api/fetch-remote-file", async (req, res) => {
  const { url, customHeaders } = req.body;
  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "Missing or invalid 'url' parameter" });
  }

  try {
    const parsedUrl = new URL(url);
    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      return res.status(400).json({ error: "Only HTTP and HTTPS protocols are supported" });
    }

    const fetchHeaders: Record<string, string> = {
      "User-Agent": "APKGuard-SecurityAnalyzer/2.0 (compatible; Android Decompiler)",
      ...(customHeaders || {}),
    };

    const response = await fetch(url, {
      method: "GET",
      headers: fetchHeaders,
      redirect: "follow",
    });

    if (!response.ok) {
      return res.status(response.status).json({
        error: `Remote server responded with status: ${response.status} ${response.statusText}`,
      });
    }

    const contentLength = response.headers.get("content-length");
    const contentDisposition = response.headers.get("content-disposition");
    const contentType = response.headers.get("content-type") || "application/octet-stream";

    let fileName = "";
    if (contentDisposition) {
      const match = contentDisposition.match(/filename\*?=(?:UTF-8'')?["']?([^"';]+)["']?/i);
      if (match && match[1]) {
        fileName = decodeURIComponent(match[1].trim());
      }
    }

    if (!fileName) {
      const pathSegments = parsedUrl.pathname.split("/").filter(Boolean);
      fileName = pathSegments[pathSegments.length - 1] || "downloaded-binary.apk";
      if (!fileName.includes(".")) {
        fileName += ".apk";
      }
    }

    // Stream the binary response directly with proper headers
    res.setHeader("Content-Type", contentType);
    res.setHeader("X-File-Name", encodeURIComponent(fileName));
    if (contentLength) {
      res.setHeader("Content-Length", contentLength);
    }
    res.setHeader("Access-Control-Expose-Headers", "X-File-Name, Content-Length, Content-Type");

    if (response.body) {
      // Node 18+ Web Streams to Node Stream piping
      const reader = response.body.getReader();
      const pump = async () => {
        while (true) {
          const { done, value } = await reader.read();
          if (done) {
            res.end();
            break;
          }
          res.write(Buffer.from(value));
        }
      };
      await pump();
    } else {
      const buffer = await response.arrayBuffer();
      res.send(Buffer.from(buffer));
    }
  } catch (err: any) {
    console.error("Remote fetch error:", err);
    if (!res.headersSent) {
      res.status(500).json({
        error: `Failed to download remote file: ${err.message || "Network error"}`,
      });
    }
  }
});

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`APK Analyzer Server running on port ${PORT}`);
  });
}

startServer();
