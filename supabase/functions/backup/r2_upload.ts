// ============================================================================
// r2_upload.ts — AWS SigV4 signing + PUT to Cloudflare R2
// ============================================================================
// Cloudflare R2 speaks the S3 API, so we use AWS Signature Version 4 to
// authenticate requests. We implement SigV4 manually (it's ~100 lines) rather
// than pulling in @aws-sdk/client-s3 (which is ~1MB+ minified — too heavy
// for a Supabase edge function).
//
// The algorithm is standard: compute a SHA-256 hash chain, derive a
// signing key by HMAC'ing the secret access key through four "stages"
// (date, region, service, "aws4_request"), then HMAC the canonical
// request + string-to-sign to produce the signature.
//
// For R2, the region is literally the string "auto" and the service is "s3".
// ============================================================================

export interface R2Config {
  accountId: string;
  accessKeyId: string;
  secretAccessKey: string;
  bucket: string;
  endpoint: string; // e.g. https://<account>.r2.cloudflarestorage.com
}

// ──────────────────────────────────────────────────────────────────────────
// Hashing + HMAC helpers
// ──────────────────────────────────────────────────────────────────────────
async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest));
}

async function hmacSha256(
  key: Uint8Array,
  message: string,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    new TextEncoder().encode(message),
  );
  return new Uint8Array(sig);
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ──────────────────────────────────────────────────────────────────────────
// SigV4 signing
// ──────────────────────────────────────────────────────────────────────────
async function deriveSigningKey(
  secretKey: string,
  dateStamp: string, // YYYYMMDD
  region: string,
  service: string,
): Promise<Uint8Array> {
  const kSecret = new TextEncoder().encode("AWS4" + secretKey);
  const kDate = await hmacSha256(kSecret, dateStamp);
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, service);
  const kSigning = await hmacSha256(kService, "aws4_request");
  return kSigning;
}

/**
 * Builds the Authorization header and X-Amz-* headers for a signed
 * PUT request to an R2 object, and returns them as a plain object.
 */
async function signRequest(
  cfg: R2Config,
  method: string,
  objectKey: string,
  body: Uint8Array,
): Promise<Record<string, string>> {
  const region = "auto";
  const service = "s3";
  const host = new URL(cfg.endpoint).host;

  const now = new Date();
  const amzDate = now.toISOString()
    .replace(/[:-]|\.\d{3}/g, ""); // e.g. 20260410T040012Z
  const dateStamp = amzDate.slice(0, 8); // 20260410

  const payloadHash = await sha256Hex(body);
  const canonicalUri = `/${cfg.bucket}/${objectKey}`;

  // Canonical request — order and whitespace matter exactly.
  const canonicalHeaders =
    `host:${host}\n` +
    `x-amz-content-sha256:${payloadHash}\n` +
    `x-amz-date:${amzDate}\n`;
  const signedHeaders = "host;x-amz-content-sha256;x-amz-date";

  const canonicalRequest = [
    method,
    canonicalUri,
    "", // canonical query string (empty for PUT object)
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  // String to sign
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest),
  ].join("\n");

  // Derive signing key and sign
  const signingKey = await deriveSigningKey(
    cfg.secretAccessKey,
    dateStamp,
    region,
    service,
  );
  const signature = bytesToHex(await hmacSha256(signingKey, stringToSign));

  const authorization =
    `AWS4-HMAC-SHA256 Credential=${cfg.accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return {
    "Host": host,
    "X-Amz-Content-Sha256": payloadHash,
    "X-Amz-Date": amzDate,
    "Authorization": authorization,
  };
}

// ──────────────────────────────────────────────────────────────────────────
// Public API: PUT an object to R2
// ──────────────────────────────────────────────────────────────────────────
export async function putObject(
  cfg: R2Config,
  objectKey: string,
  body: Uint8Array,
  contentType = "application/octet-stream",
): Promise<{ ok: boolean; status: number; statusText: string; error?: string }> {
  const headers = await signRequest(cfg, "PUT", objectKey, body);
  headers["Content-Type"] = contentType;
  headers["Content-Length"] = String(body.length);

  const url = `${cfg.endpoint}/${cfg.bucket}/${objectKey}`;
  const response = await fetch(url, {
    method: "PUT",
    headers,
    body,
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => "");
    return {
      ok: false,
      status: response.status,
      statusText: response.statusText,
      error: errorText.slice(0, 500),
    };
  }
  return { ok: true, status: response.status, statusText: response.statusText };
}
