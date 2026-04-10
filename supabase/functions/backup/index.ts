// ============================================================================
// index.ts — main handler for the `backup` edge function
// ============================================================================
// Pipeline:
//   1. Verify the X-Webhook-Secret header against Vault (reject if missing/wrong)
//   2. Load R2 credentials + encryption key from Vault
//   3. Insert a 'running' row into backup_log (get its id)
//   4. Build the backup payload from critical tables
//   5. JSON serialize -> gzip -> AES-256-GCM encrypt
//   6. PUT the encrypted blob to R2
//   7. Update backup_log row to 'success' (or 'error' on any failure)
//
// Invoked by pg_cron via pg_net.http_post() once a day at 04:00 UTC.
// Can also be invoked manually for testing with trigger='manual' in body.
// ============================================================================

import { encryptBlob, gzipBytes, utf8Encode } from "./crypto.ts";
import { putObject, R2Config } from "./r2_upload.ts";
import {
  buildBackupPayload,
  buildObjectKey,
  makeServiceClient,
} from "./db_export.ts";

// ──────────────────────────────────────────────────────────────────────────
// Vault secret loader
// ──────────────────────────────────────────────────────────────────────────
// Edge functions access Vault by querying the `vault.decrypted_secrets` view
// as service_role via supabase-js. We load all secrets upfront in one batch.
async function loadSecretsFromVault(
  client: ReturnType<typeof makeServiceClient>,
): Promise<Record<string, string>> {
  // supabase-js can't query cross-schema views directly — use RPC or raw SQL.
  // We expose a tiny helper function via a one-off SQL call. Simpler: query
  // the view through a SECURITY DEFINER RPC we create alongside this deploy.
  // For now, use the generic `rpc` to call a function we'll define below.
  const { data, error } = await client.rpc("get_backup_secrets");
  if (error) {
    throw new Error(`vault read failed: ${error.message}`);
  }
  if (!data || typeof data !== "object") {
    throw new Error("vault returned empty secret set");
  }
  return data as Record<string, string>;
}

// ──────────────────────────────────────────────────────────────────────────
// backup_log helpers
// ──────────────────────────────────────────────────────────────────────────
async function insertBackupLogRunning(
  client: ReturnType<typeof makeServiceClient>,
  triggerSource: string,
): Promise<number> {
  const { data, error } = await client
    .from("backup_log")
    .insert({ status: "running", trigger_source: triggerSource })
    .select("id")
    .single();
  if (error || !data) {
    throw new Error(`backup_log insert failed: ${error?.message ?? "no data"}`);
  }
  return data.id as number;
}

async function markBackupSuccess(
  client: ReturnType<typeof makeServiceClient>,
  id: number,
  objectKey: string,
  bytesWritten: number,
  rowCounts: Record<string, number>,
): Promise<void> {
  await client
    .from("backup_log")
    .update({
      status: "success",
      completed_at: new Date().toISOString(),
      r2_object_key: objectKey,
      bytes_written: bytesWritten,
      rows_exported: rowCounts,
    })
    .eq("id", id);
}

async function markBackupError(
  client: ReturnType<typeof makeServiceClient>,
  id: number,
  error: string,
): Promise<void> {
  await client
    .from("backup_log")
    .update({
      status: "error",
      completed_at: new Date().toISOString(),
      error_message: error.slice(0, 2000),
    })
    .eq("id", id);
}

// ──────────────────────────────────────────────────────────────────────────
// Main HTTP handler
// ──────────────────────────────────────────────────────────────────────────
Deno.serve(async (req: Request): Promise<Response> => {
  // Only POST is allowed
  if (req.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const providedSecret = req.headers.get("X-Webhook-Secret") ?? "";
  const client = makeServiceClient();

  // Parse body (best effort — used only for trigger_source)
  let triggerSource = "unknown";
  try {
    const body = await req.json();
    if (typeof body?.trigger === "string") triggerSource = body.trigger;
  } catch (_) {
    // body absent or malformed — still let secret verification decide
  }

  // Load secrets from Vault
  let secrets: Record<string, string>;
  try {
    secrets = await loadSecretsFromVault(client);
  } catch (err) {
    return new Response(
      JSON.stringify({ error: "vault read failed", detail: String(err) }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }

  // Verify webhook secret (constant-time compare would be nicer, but
  // timing attacks on a 256-bit random secret over TLS are not realistic)
  if (providedSecret !== secrets.backup_webhook_secret) {
    return new Response(
      JSON.stringify({ error: "unauthorized" }),
      { status: 401, headers: { "Content-Type": "application/json" } },
    );
  }

  // Create backup_log row so failures are recorded even if we crash midway
  let logId: number;
  try {
    logId = await insertBackupLogRunning(client, triggerSource);
  } catch (err) {
    return new Response(
      JSON.stringify({ error: "backup_log init failed", detail: String(err) }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }

  // Main backup pipeline
  try {
    const payload = await buildBackupPayload(client, triggerSource);
    const json = JSON.stringify(payload);
    const jsonBytes = utf8Encode(json);
    const gzipped = await gzipBytes(jsonBytes);
    const encrypted = await encryptBlob(gzipped, secrets.backup_encryption_key);

    const r2Config: R2Config = {
      accountId: secrets.r2_account_id,
      accessKeyId: secrets.r2_access_key_id,
      secretAccessKey: secrets.r2_secret_access_key,
      bucket: secrets.r2_bucket,
      endpoint: secrets.r2_endpoint,
    };

    const objectKey = buildObjectKey(triggerSource);
    const uploadResult = await putObject(
      r2Config,
      objectKey,
      encrypted,
      "application/octet-stream",
    );

    if (!uploadResult.ok) {
      throw new Error(
        `R2 upload failed: ${uploadResult.status} ${uploadResult.statusText} — ${uploadResult.error ?? ""}`,
      );
    }

    await markBackupSuccess(
      client,
      logId,
      objectKey,
      encrypted.length,
      payload.row_counts,
    );

    return new Response(
      JSON.stringify({
        ok: true,
        backup_log_id: logId,
        object_key: objectKey,
        bytes_written: encrypted.length,
        row_counts: payload.row_counts,
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    await markBackupError(client, logId, msg).catch(() => {});
    return new Response(
      JSON.stringify({ error: "backup failed", detail: msg, backup_log_id: logId }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }
});
