/**
 * main.ts — "The World Today", 25 November 2026 edition.
 *
 * Node 22, standard library only. This program does not draw anything:
 * the front page is the JPEG stored beside this file (entry.png). What
 * this program does is prove, before shipping it, that the file is the
 * exact edition it claims to be — an edition-stamp auditor:
 *
 *   1. The file's byte count and SHA-256 must match the pinned manifest.
 *   2. It must open with SOI and carry a JFIF APP0 segment (version 1.1
 *      or 1.2) as its first segment.
 *   3. A census of the header tables must hold: exactly two DQT tables,
 *      at least two DHT tables, exactly one baseline SOF0 frame of
 *      1024x1024 with three components.
 *   4. A COM segment must carry the edition stamp
 *      "THE WORLD TODAY - 25 NOVEMBER 2026 - SHENZHOU-24", and it must
 *      appear before the start of scan.
 *   5. The entropy-coded scan is walked byte by byte, honouring stuffed
 *      FF00 bytes, until the EOI marker — which must be the file's final
 *      two bytes.
 *
 * Only a file that passes every check is written to
 * $MAKEFUN_OUTPUT_DIR/entry.png (default: ./output/entry.png).
 */

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const MANIFEST = {
  bytes: 341141,
  sha256:
    "ae55aeaa147816616136ce72c08befdc76e36a1e49cc25ee3d9734744b06487d",
  width: 1024,
  height: 1024,
};

const EDITION_STAMP = "THE WORLD TODAY - 25 NOVEMBER 2026 - SHENZHOU-24";

const MARKERS = {
  SOI: 0xd8,
  EOI: 0xd9,
  SOS: 0xda,
  DQT: 0xdb,
  DHT: 0xc4,
  DRI: 0xdd,
  SOF0: 0xc0,
  APP0: 0xe0,
  COM: 0xfe,
} as const;

function fail(message: string): never {
  throw new Error(`edition audit failed: ${message}`);
}

function sha256Hex(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

interface Census {
  dqtTables: number;
  dhtTables: number;
  sofCount: number;
  width: number;
  height: number;
  components: number;
  sosComponents: number;
  driSeen: boolean;
  restartMarkersSeen: number;
  comStamps: string[];
  sawSos: boolean;
}

/** Parse one marker segment starting at `pos` (buf[pos] === 0xFF). */
function readSegment(buf: Buffer, pos: number): { marker: number; end: number } {
  if (buf[pos] !== 0xff) fail(`expected 0xFF at offset ${pos}`);
  const marker = buf[pos + 1];
  // Standalone markers (SOI, EOI, RSTn) carry no length field.
  if (marker === MARKERS.SOI || marker === MARKERS.EOI ||
      (marker >= 0xd0 && marker <= 0xd7)) {
    return { marker, end: pos + 2 };
  }
  const length = buf.readUInt16BE(pos + 2);
  if (length < 2 || pos + 2 + length > buf.length) {
    fail(`segment 0xFF${marker.toString(16)} at ${pos} has a bad length`);
  }
  return { marker, end: pos + 2 + length };
}

function audit(buf: Buffer): Census {
  if (buf.length !== MANIFEST.bytes) {
    fail(`byte count ${buf.length}, manifest says ${MANIFEST.bytes}`);
  }
  if (sha256Hex(buf) !== MANIFEST.sha256) {
    fail("SHA-256 does not match the pinned manifest");
  }
  if (buf[0] !== 0xff || buf[1] !== MARKERS.SOI) {
    fail("file does not start with SOI (FFD8)");
  }

  const census: Census = {
    dqtTables: 0,
    dhtTables: 0,
    sofCount: 0,
    width: 0,
    height: 0,
    components: 0,
    sosComponents: 0,
    driSeen: false,
    restartMarkersSeen: 0,
    comStamps: [],
    sawSos: false,
  };

  let pos = 2;
  let app0Seen = false;
  while (pos < buf.length) {
    if (buf[pos] !== 0xff) fail(`lost marker sync at offset ${pos}`);
    // Skip fill bytes (repeated 0xFF) between segments.
    while (buf[pos + 1] === 0xff) pos += 1;
    const { marker, end } = readSegment(buf, pos);
    const body = buf.subarray(pos + 4, end);

    if (!app0Seen && marker !== MARKERS.APP0) {
      fail("first segment is not APP0");
    }
    if (marker === MARKERS.APP0) {
      app0Seen = true;
      if (body.subarray(0, 5).toString("ascii") !== "JFIF\0") {
        fail("APP0 segment is not JFIF");
      }
      const [major, minor] = [body[5], body[6]];
      if (!((major === 1 && minor === 1) || (major === 1 && minor === 2))) {
        fail(`unsupported JFIF version ${major}.${minor}`);
      }
    } else if (marker === MARKERS.DQT) {
      // Each DQT segment holds 65 bytes per table (1 info + 64 values).
      census.dqtTables += Math.floor(body.length / 65);
    } else if (marker === MARKERS.DHT) {
      census.dhtTables += 1;
    } else if (marker === MARKERS.SOF0) {
      census.sofCount += 1;
      census.height = buf.readUInt16BE(pos + 5);
      census.width = buf.readUInt16BE(pos + 7);
      census.components = body[5]; // precision, height, width, then count
    } else if (marker === MARKERS.DRI) {
      census.driSeen = true;
    } else if (marker === MARKERS.COM) {
      census.comStamps.push(body.toString("ascii"));
    } else if (marker === MARKERS.SOS) {
      census.sawSos = true;
      census.sosComponents = body[0]; // Ns: components in this scan
      // The entropy-coded scan runs from here to EOI. Walk it honouring
      // stuffed FF00 bytes; any other 0xFF byte must start a marker.
      let i = end;
      let foundEoi = false;
      while (i < buf.length - 1) {
        if (buf[i] !== 0xff) {
          i += 1;
          continue;
        }
        const next = buf[i + 1];
        if (next === 0x00) {
          i += 2; // stuffed byte: literal 0xFF in the scan data
          continue;
        }
        if (next === MARKERS.EOI) {
          if (i + 2 !== buf.length) fail("bytes trail the EOI marker");
          foundEoi = true;
          break;
        }
        if (next >= 0xd0 && next <= 0xd7) {
          census.restartMarkersSeen += 1;
          i += 2; // restart marker: part of the scan
          continue;
        }
        fail(`unexpected marker 0xFF${next.toString(16)} inside scan data`);
      }
      if (!foundEoi) fail("scan data ends without EOI");
      break;
    }
    pos = end;
  }

  if (census.dqtTables !== 2) {
    fail(`DQT census: ${census.dqtTables} tables, expected 2`);
  }
  if (census.dhtTables < 2) {
    fail(`DHT census: ${census.dhtTables} tables, expected at least 2`);
  }
  if (census.sofCount !== 1) {
    fail(`SOF0 census: ${census.sofCount} frames, expected 1`);
  }
  if (census.width !== MANIFEST.width || census.height !== MANIFEST.height) {
    fail(`frame is ${census.width}x${census.height}, manifest says ` +
         `${MANIFEST.width}x${MANIFEST.height}`);
  }
  if (census.components !== 3) {
    fail(`frame has ${census.components} components, expected 3`);
  }
  if (!census.comStamps.includes(EDITION_STAMP)) {
    fail("no COM segment carries the edition stamp");
  }
  // Restart markers and the DRI segment must agree: a file that declares
  // a restart interval must actually use restart markers, and one that
  // uses them must declare the interval.
  if (!census.driSeen && census.restartMarkersSeen > 0) {
    fail("restart markers in the scan but no DRI segment in the header");
  }
  if (census.driSeen && census.restartMarkersSeen === 0) {
    fail("DRI segment present but no restart markers in the scan");
  }
  if (!census.sawSos) fail("no SOS segment found");
  if (census.sosComponents !== census.components) {
    fail(`SOS carries ${census.sosComponents} components, SOF0 declares ` +
         `${census.components}`);
  }
  return census;
}

function main(): void {
  const here = dirname(fileURLToPath(import.meta.url));
  const source = join(here, "entry.png");
  const buf = readFileSync(source);
  const census = audit(buf);

  const outDir = process.env.MAKEFUN_OUTPUT_DIR ?? join(here, "output");
  mkdirSync(outDir, { recursive: true });
  const outPath = join(outDir, "entry.png");
  writeFileSync(outPath, buf);

  // Read the copy back and compare byte for byte.
  const back = readFileSync(outPath);
  if (!back.equals(buf)) fail("written copy differs from the audited bytes");

  console.log(
    `entry.png: ${buf.length} bytes, ${census.width}x${census.height}, ` +
    `sha256 ${sha256Hex(buf)} -> ${outPath}`,
  );
}

main();
