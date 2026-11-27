// Measures raw, whitespace/comment-minified, and gzip-9 byte sizes of mnc1_sync.js
// and writes the minified build to /tmp/mynote-s-clip-1/mnc1_sync.min.js for verification.
"use strict";
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const srcPath = path.join(__dirname, "mnc1_sync.js");
const raw = fs.readFileSync(srcPath, "utf8");

// Conservative JS whitespace/comment minifier (preserves string literals verbatim).
function minifyJs(code) {
  let out = "";
  let i = 0;
  const n = code.length;
  let inStr = null;
  while (i < n) {
    const ch = code[i];
    if (inStr) {
      out += ch;
      if (ch === "\\" && i + 1 < n) {
        out += code[++i];
      } else if (ch === inStr) {
        inStr = null;
      }
      i++;
      continue;
    }
    if (ch === '"' || ch === "'") {
      inStr = ch;
      out += ch;
      i++;
      continue;
    }
    if (ch === "/" && code[i + 1] === "/") {
      i += 2;
      while (i < n && code[i] !== "\n") i++;
      continue;
    }
    if (ch === "/" && code[i + 1] === "*") {
      i += 2;
      while (i + 1 < n && !(code[i] === "*" && code[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    if (ch === "\r" || ch === "\n" || ch === "\t" || ch === " ") {
      while (i < n && (code[i] === "\r" || code[i] === "\n" || code[i] === "\t" || code[i] === " ")) i++;
      const prev = out[out.length - 1] || "";
      const next = code[i] || "";
      const needSpace =
        (/[A-Za-z0-9_$]/.test(prev) && /[A-Za-z0-9_$]/.test(next)) ||
        (prev === "+" && next === "+") ||
        (prev === "-" && next === "-");
      if (needSpace) out += " ";
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}

const min = minifyJs(raw);
const rawBuf = Buffer.from(raw, "utf8");
const minBuf = Buffer.from(min, "utf8");
const rawGz = zlib.gzipSync(rawBuf, { level: 9 });
const minGz = zlib.gzipSync(minBuf, { level: 9 });

const outMinPath = process.argv[2];
if (outMinPath) {
  fs.writeFileSync(outMinPath, min, "utf8");
}

console.log(
  JSON.stringify(
    {
      file: "spikes/s-clip-1-ios-shortcuts/mnc1_sync.js",
      lines: raw.split("\n").length - 1,
      raw_bytes: rawBuf.length,
      raw_kib: Number((rawBuf.length / 1024).toFixed(2)),
      minified_bytes: minBuf.length,
      minified_kib: Number((minBuf.length / 1024).toFixed(2)),
      raw_gzip9_bytes: rawGz.length,
      minified_gzip9_bytes: minGz.length,
    },
    null,
    2
  )
);
