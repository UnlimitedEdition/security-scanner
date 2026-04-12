// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
// ============================================================================
// crypto.ts — AES-256-GCM encryption via Web Crypto API
// ============================================================================
// Deno's runtime includes the Web Crypto API natively, so no imports needed.
// We use AES-256-GCM because:
//   - Authenticated encryption (tamper detection built in)
//   - Hardware-accelerated on most modern CPUs
//   - Standard, well-audited primitive
//
// The encrypted blob format we write to R2 is:
//
//   [ 12 bytes IV ] [ ciphertext + 16-byte GCM auth tag ]
//
// The restore script reads the same layout: first 12 bytes are the IV,
// everything after is what we pass to decrypt().
// ============================================================================

/**
 * Converts a hex-encoded string (from the Vault-stored key) into raw bytes.
 * Throws if the hex is malformed or not 32 bytes (256 bits).
 */
function hexToBytes(hex: string): Uint8Array {
  if (hex.length !== 64) {
    throw new Error(
      `encryption key must be 64 hex chars (32 bytes), got ${hex.length}`,
    );
  }
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`invalid hex at position ${i * 2}`);
    }
    bytes[i] = byte;
  }
  return bytes;
}

/**
 * Imports the hex key as a non-extractable CryptoKey for AES-GCM.
 * Non-extractable means even if someone gets a reference to the key object
 * in-memory, they can't read the raw bytes back out.
 */
async function importKey(hexKey: string): Promise<CryptoKey> {
  const rawKey = hexToBytes(hexKey);
  return await crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM" },
    false, // non-extractable
    ["encrypt"],
  );
}

/**
 * Encrypts a plaintext Uint8Array and returns the blob we'll upload to R2.
 *
 * Layout: [ 12 bytes IV ] [ ciphertext (N bytes) + 16 bytes GCM auth tag ]
 *
 * The IV is fresh random for every call — NEVER reuse an IV with the same
 * key. 96 bits of randomness gives collision probability ~2^-48 after
 * 2^24 encryptions, which for our use case (one backup per day) is fine
 * for millennia.
 */
export async function encryptBlob(
  plaintext: Uint8Array,
  hexKey: string,
): Promise<Uint8Array> {
  const key = await importKey(hexKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintext,
  );
  const ciphertext = new Uint8Array(ciphertextBuffer);

  // Concatenate IV || ciphertext+tag into a single blob.
  const blob = new Uint8Array(iv.length + ciphertext.length);
  blob.set(iv, 0);
  blob.set(ciphertext, iv.length);
  return blob;
}

/**
 * Gzip-compresses a Uint8Array using Deno's native CompressionStream.
 * Run BEFORE encryption — encrypted data is incompressible, so compressing
 * after is pointless. JSON is highly compressible (~10x for our schemas).
 */
export async function gzipBytes(data: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([data]).stream().pipeThrough(
    new CompressionStream("gzip"),
  );
  const compressedBuffer = await new Response(stream).arrayBuffer();
  return new Uint8Array(compressedBuffer);
}

/**
 * Helper: UTF-8 encode a string to Uint8Array for the crypto pipeline.
 */
export function utf8Encode(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}
