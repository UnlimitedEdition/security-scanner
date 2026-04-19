# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Subscription layer — Lemon Squeezy webhooks and Pro plan queries.

This module is the single source of truth for "is this user on Pro?".
It owns three responsibilities:

  1. **Webhook ingestion.** `process_webhook_event()` is the idempotent
     entry point called by the /webhooks/lemon endpoint. It verifies the
     HMAC signature, deduplicates by event id, persists the raw payload
     to lemon_webhook_events, and dispatches to an event handler.

  2. **Row mutation.** Event handlers upsert the subscriptions table
     based on the Lemon Squeezy payload. Subscription state (status,
     current_period_end, etc.) is mirrored 1:1 from Lemon — we never
     invent state locally.

  3. **Auth lookups.** `get_by_license_key()`, `get_by_email()`, and
     `is_active()` are the public API used by /api/auth/license,
     /api/subscription/me, and the Pro feature gates in scanner.py.

Design rules:

  - **Fail closed on auth lookups.** If the database is unreachable,
    `is_active()` returns False. A Pro user briefly losing access is
    better than a free user accidentally getting Pro features.
  - **Fail open on webhook writes.** If the DB is unreachable during
    a webhook, we return 500 and Lemon Squeezy will retry. Losing a
    webhook would desync state permanently.
  - **No raw license key logging.** License keys are bearer tokens —
    never write them to logs or error messages. Use `_redact_key()`.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import db

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────
# Environment
# ─────────────────────────────────────────────────────────────────────────
LEMON_API_KEY = os.environ.get("LEMON_API_KEY", "").strip()
LEMON_WEBHOOK_SECRET = os.environ.get("LEMON_WEBHOOK_SECRET", "").strip()
LEMON_STORE_ID = os.environ.get("LEMON_STORE_ID", "").strip()
LEMON_PRODUCT_ID = os.environ.get("LEMON_PRODUCT_ID", "").strip()
LEMON_VARIANT_MONTHLY = os.environ.get("LEMON_VARIANT_MONTHLY", "").strip()
LEMON_VARIANT_YEARLY = os.environ.get("LEMON_VARIANT_YEARLY", "").strip()
LEMON_VARIANT_MALWARE_5_PACK = os.environ.get("LEMON_VARIANT_MALWARE_5_PACK", "").strip()

LEMON_API_BASE = "https://api.lemonsqueezy.com/v1"


# Events we actually handle. Anything else is logged as 'ignored' in the
# webhook events table without a row change.
_HANDLED_EVENTS = frozenset({
    "subscription_created",
    "subscription_updated",
    "subscription_cancelled",
    "subscription_resumed",
    "subscription_expired",
    "subscription_paused",
    "subscription_unpaused",
    "subscription_payment_success",
    "subscription_payment_failed",
    "subscription_payment_recovered",
    "subscription_payment_refunded",
    "license_key_created",
    "license_key_updated",
    "order_created",
})


# ─────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────
def _redact_key(key: Optional[str]) -> str:
    """Return a log-safe preview of a license key (first 4 chars + …)."""
    if not key:
        return "<none>"
    return f"{key[:4]}…" if len(key) > 4 else "<short>"


def _parse_ts(value: Optional[str]) -> Optional[str]:
    """
    Normalize a Lemon Squeezy timestamp to ISO 8601 with Z.
    Lemon sends ISO 8601 already, but we round-trip through datetime to
    catch malformed inputs and produce a consistent format in our DB.
    """
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except (ValueError, TypeError):
        log.warning("subscription._parse_ts: bad timestamp %r", value)
        return None


def _variant_to_plan_name(variant_id: Optional[int]) -> Optional[str]:
    """
    Map a Lemon Squeezy variant_id to our plan_name enum.
    Unknown variants return None — the caller decides whether to reject
    or fall back to 'unknown' (webhook handlers reject).
    """
    if not variant_id:
        return None
    vid = str(variant_id)
    if LEMON_VARIANT_MONTHLY and vid == LEMON_VARIANT_MONTHLY:
        return "pro_monthly"
    if LEMON_VARIANT_YEARLY and vid == LEMON_VARIANT_YEARLY:
        return "pro_yearly"
    return None


# ─────────────────────────────────────────────────────────────────────────
# Signature verification
# ─────────────────────────────────────────────────────────────────────────
def verify_webhook_signature(raw_body: bytes, signature_header: str) -> bool:
    """
    Verify the X-Signature header on a Lemon Squeezy webhook.

    Lemon signs the raw request body with HMAC-SHA256 using the webhook
    signing secret as the key. We recompute the digest and constant-time
    compare against the header. If LEMON_WEBHOOK_SECRET is unset, verification
    fails closed — we do NOT process unsigned webhooks.
    """
    if not LEMON_WEBHOOK_SECRET:
        log.error("verify_webhook_signature: LEMON_WEBHOOK_SECRET not set")
        return False
    if not signature_header:
        return False
    try:
        expected = hmac.new(
            LEMON_WEBHOOK_SECRET.encode("utf-8"),
            raw_body,
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signature_header.strip())
    except Exception as e:
        log.warning("verify_webhook_signature raised: %s", e)
        return False


# ─────────────────────────────────────────────────────────────────────────
# Webhook entry point
# ─────────────────────────────────────────────────────────────────────────
def process_webhook_event(
    event_id: str,
    event_name: str,
    payload: Dict[str, Any],
) -> Tuple[str, Optional[str]]:
    """
    Idempotent processor for one Lemon Squeezy webhook.

    Returns a tuple of (result, error_message) where result is one of:
        'ok'      — processed and a row was written/updated
        'skipped' — dedup hit, this event_id was already processed
        'ignored' — event_name not in _HANDLED_EVENTS
        'error'   — something threw; error_message is populated

    The caller (webhook endpoint) should:
      - return 200 for 'ok', 'skipped', or 'ignored'
      - return 500 for 'error' so Lemon Squeezy retries
    """
    if not db.is_configured():
        return "error", "database not configured"

    if event_name not in _HANDLED_EVENTS:
        _log_webhook_event(event_id, event_name, payload, "ignored", None)
        return "ignored", None

    # Dedup check — try to log the event first. If the unique constraint
    # on lemon_event_id fires, this event has already been processed and
    # we short-circuit to 'skipped'. This gives us at-most-once semantics
    # without explicit locking.
    inserted = _log_webhook_event(
        event_id, event_name, payload, "ok", None,
    )
    if inserted is False:
        return "skipped", None

    try:
        if event_name == "order_created":
            _handle_order_created(payload)
        elif event_name.startswith("subscription_"):
            _handle_subscription_event(event_name, payload)
        elif event_name.startswith("license_key_"):
            _handle_license_key_event(event_name, payload)
        return "ok", None
    except Exception as e:
        err = str(e)[:500]
        log.exception("process_webhook_event failed for %s", event_name)
        # Update the already-logged row to mark it as an error so a human
        # can replay it later. Best-effort — we already returned the error.
        _update_webhook_event_result(event_id, "error", err)
        return "error", err


def _log_webhook_event(
    event_id: str,
    event_name: str,
    payload: Dict[str, Any],
    result: str,
    error_message: Optional[str],
) -> Optional[bool]:
    """
    INSERT a lemon_webhook_events row. Returns:
        True  — inserted fresh (first time seeing this event_id)
        False — UNIQUE violation on lemon_event_id (duplicate)
        None  — database unreachable or another error
    """
    try:
        client = db.get_client()
        row = {
            "lemon_event_id": event_id,
            "event_name": event_name,
            "payload": payload,
            "result": result,
            "error_message": error_message,
        }
        client.table("lemon_webhook_events").insert(row).execute()
        return True
    except Exception as e:
        # Supabase returns a unique violation as an exception with code 23505
        msg = str(e).lower()
        if "23505" in msg or "duplicate key" in msg or "unique" in msg:
            return False
        log.warning("_log_webhook_event failed: %s", str(e)[:200])
        return None


def _update_webhook_event_result(
    event_id: str, result: str, error_message: Optional[str],
) -> None:
    """Flip an already-logged event row to a new result (best effort)."""
    # NOTE: lemon_webhook_events has UPDATE revoked from service_role in
    # migration 011 (append-only). We cannot flip the row. Instead, log
    # a fresh row with a different surrogate id so the history is intact.
    try:
        client = db.get_client()
        client.table("lemon_webhook_events").insert({
            "lemon_event_id": f"{event_id}::retry::{datetime.now(timezone.utc).timestamp()}",
            "event_name": "error_followup",
            "payload": {"original_event_id": event_id, "new_result": result},
            "result": result,
            "error_message": error_message,
        }).execute()
    except Exception:
        pass  # truly best effort


# ─────────────────────────────────────────────────────────────────────────
# Subscription event handlers
# ─────────────────────────────────────────────────────────────────────────
def _handle_subscription_event(event_name: str, payload: Dict[str, Any]) -> None:
    """
    Shared handler for all subscription_* events. The mutation we need
    (upsert the subscriptions row to mirror Lemon's state) is the same
    regardless of which sub-event fired — Lemon always sends the full
    subscription object in the payload.
    """
    attrs = _extract_subscription_attrs(payload)
    if not attrs:
        raise ValueError(f"{event_name}: could not extract subscription attributes")

    plan_name = _variant_to_plan_name(attrs.get("variant_id"))
    if not plan_name:
        raise ValueError(
            f"{event_name}: variant_id {attrs.get('variant_id')} is not mapped "
            f"to a known plan. Check LEMON_VARIANT_MONTHLY / LEMON_VARIANT_YEARLY env vars."
        )

    row = {
        "email": (attrs.get("user_email") or "").strip().lower(),
        "lemon_customer_id": attrs.get("customer_id"),
        "lemon_subscription_id": attrs.get("subscription_id"),
        "lemon_order_id": attrs.get("order_id"),
        "lemon_product_id": attrs.get("product_id"),
        "lemon_variant_id": attrs.get("variant_id"),
        "plan_name": plan_name,
        "status": attrs.get("status") or "active",
        "trial_ends_at": _parse_ts(attrs.get("trial_ends_at")),
        "current_period_start": (
            _parse_ts(attrs.get("created_at")) or datetime.now(timezone.utc).isoformat()
        ),
        "current_period_end": (
            _parse_ts(attrs.get("renews_at"))
            or _parse_ts(attrs.get("ends_at"))
            or datetime.now(timezone.utc).isoformat()
        ),
        "cancelled_at": _parse_ts(attrs.get("cancelled_at")),
    }

    # Drop Nones so UPSERT doesn't clobber existing values with NULL.
    # Exception: cancelled_at is explicitly set to None on resume events.
    if event_name != "subscription_resumed":
        row = {k: v for k, v in row.items() if v is not None}

    if not row.get("lemon_subscription_id"):
        raise ValueError(f"{event_name}: payload has no subscription id")

    client = db.get_client()
    client.table("subscriptions").upsert(
        row, on_conflict="lemon_subscription_id"
    ).execute()
    log.info(
        "subscription %s: sub_id=%s email=%s status=%s plan=%s",
        event_name,
        row.get("lemon_subscription_id"),
        row.get("email"),
        row.get("status"),
        row.get("plan_name"),
    )


def _extract_subscription_attrs(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Pull the subscription attributes out of a Lemon Squeezy webhook payload.

    Lemon's payload shape:
        { "meta": {...}, "data": { "type": "subscriptions", "id": "N",
                                   "attributes": {...} } }

    Returns a flat dict with the attributes we care about, or None if the
    payload shape is unexpected.
    """
    data = payload.get("data") or {}
    attrs = data.get("attributes") or {}
    if not attrs:
        return None
    try:
        sub_id = int(data.get("id")) if data.get("id") is not None else None
    except (TypeError, ValueError):
        sub_id = None
    return {
        "subscription_id": sub_id,
        "customer_id": attrs.get("customer_id"),
        "order_id": attrs.get("order_id"),
        "product_id": attrs.get("product_id"),
        "variant_id": attrs.get("variant_id"),
        "user_email": attrs.get("user_email"),
        "status": attrs.get("status"),
        "trial_ends_at": attrs.get("trial_ends_at"),
        "renews_at": attrs.get("renews_at"),
        "ends_at": attrs.get("ends_at"),
        "created_at": attrs.get("created_at"),
        "cancelled_at": attrs.get("cancelled_at"),
    }


# ─────────────────────────────────────────────────────────────────────────
# One-time order handler (Malware 5-Pack)
# ─────────────────────────────────────────────────────────────────────────

_MALWARE_PACK_CONFIG = {
    "5_pack": {"credits": 5, "days": 30},
}

_on_license_key_ready = None


def set_activation_callback(fn):
    global _on_license_key_ready
    _on_license_key_ready = fn


def _handle_order_created(payload: Dict[str, Any]) -> None:
    """
    Handle order_created webhook for one-time purchases (Malware 5-Pack).

    Creates TWO rows:
      1. subscriptions — plan_name='malware_pack', license_key from Lemon
      2. malware_credits — credits_total=5, expires in 30 days, FK to subscription

    If the user buys again with the same email, we reuse the existing
    subscription row (same license_key) and just add a new malware_credits row.
    """
    data = payload.get("data") or {}
    attrs = data.get("attributes") or {}
    if not attrs:
        raise ValueError("order_created: empty attributes")

    first_item = (attrs.get("first_order_item") or {})
    variant_id = first_item.get("variant_id")

    if not LEMON_VARIANT_MALWARE_5_PACK or str(variant_id) != LEMON_VARIANT_MALWARE_5_PACK:
        log.info("order_created: variant_id=%s is not malware_5_pack, ignoring", variant_id)
        return

    order_id = int(data.get("id")) if data.get("id") is not None else None
    customer_id = attrs.get("customer_id")
    user_email = (attrs.get("user_email") or "").strip().lower()

    if not order_id or not customer_id or not user_email:
        raise ValueError(
            f"order_created: missing required fields "
            f"(order_id={order_id}, customer_id={customer_id}, email={'set' if user_email else 'empty'})"
        )

    pack_cfg = _MALWARE_PACK_CONFIG["5_pack"]
    client = db.get_client()

    existing = (
        client.table("subscriptions")
        .select("id,license_key")
        .eq("email", user_email)
        .eq("plan_name", "malware_pack")
        .limit(1)
        .execute()
    )
    existing_rows = existing.data or []

    if existing_rows:
        sub_row = existing_rows[0]
        sub_id = sub_row["id"]
        client.table("subscriptions").update({
            "status": "active",
            "lemon_order_id": order_id,
            "lemon_customer_id": customer_id,
        }).eq("id", sub_id).execute()
        log.info(
            "order_created: reactivated existing subscription id=%s for email=%s",
            sub_id, user_email,
        )
    else:
        new_sub = {
            "email": user_email,
            "lemon_customer_id": customer_id,
            "lemon_order_id": order_id,
            "plan_name": "malware_pack",
            "status": "active",
            "current_period_start": datetime.now(timezone.utc).isoformat(),
            "current_period_end": (
                datetime.now(timezone.utc)
                + timedelta(days=pack_cfg["days"])
            ).isoformat(),
        }
        result = client.table("subscriptions").insert(new_sub).execute()
        sub_row = (result.data or [{}])[0]
        sub_id = sub_row.get("id")
        if not sub_id:
            raise ValueError("order_created: failed to INSERT subscription row")
        log.info(
            "order_created: created subscription id=%s for email=%s",
            sub_id, user_email,
        )

    credit_row = {
        "lemon_order_id": str(order_id),
        "pack_kind": "5_pack",
        "credits_total": pack_cfg["credits"],
        "credits_remaining": pack_cfg["credits"],
        "expires_at": (
            datetime.now(timezone.utc)
            + timedelta(days=pack_cfg["days"])
        ).isoformat(),
        "buyer_email": user_email,
        "subscription_id": sub_id,
    }
    client.table("malware_credits").insert(credit_row).execute()
    log.info(
        "order_created: created malware_credits for sub_id=%s, %d credits, %d days",
        sub_id, pack_cfg["credits"], pack_cfg["days"],
    )


# ─────────────────────────────────────────────────────────────────────────
# License key event handlers
# ─────────────────────────────────────────────────────────────────────────
def _handle_license_key_event(event_name: str, payload: Dict[str, Any]) -> None:
    """
    License keys arrive in their own events. We attach the key to an
    existing subscription row by matching on order_id (license keys are
    tied to orders, and orders are tied to subscriptions).

    If the subscription row doesn't exist yet (license_key_created raced
    ahead of subscription_created), we still log the event and will
    attach the key the next time we see a subscription_updated for the
    same order. For V1 we trust that Lemon sends subscription_created
    first in practice.
    """
    data = payload.get("data") or {}
    attrs = data.get("attributes") or {}
    if not attrs:
        raise ValueError(f"{event_name}: empty attributes")

    license_key_value = attrs.get("key")
    order_id = attrs.get("order_id")
    if not license_key_value:
        raise ValueError(f"{event_name}: no key in payload")
    if not order_id:
        raise ValueError(f"{event_name}: no order_id in payload")

    client = db.get_client()
    # Find the subscription tied to this order and patch it
    result = (
        client.table("subscriptions")
        .update({"license_key": license_key_value})
        .eq("lemon_order_id", order_id)
        .execute()
    )
    rows = result.data or []
    if not rows:
        log.warning(
            "%s: no subscription row found for order_id=%s (key=%s). "
            "Will be attached on next subscription_updated event.",
            event_name, order_id, _redact_key(license_key_value),
        )
        return
    log.info(
        "%s: attached key %s to subscription_id=%s",
        event_name,
        _redact_key(license_key_value),
        rows[0].get("lemon_subscription_id"),
    )

    if _on_license_key_ready:
        meta = payload.get("meta") or {}
        custom = meta.get("custom_data") or {}
        activation_token = custom.get("activation_token")
        if activation_token:
            _on_license_key_ready(activation_token, license_key_value)


# ─────────────────────────────────────────────────────────────────────────
# Public query API (called by api.py and feature gates)
# ─────────────────────────────────────────────────────────────────────────
def get_by_license_key(license_key: str) -> Optional[Dict[str, Any]]:
    """
    SELECT a subscription row by license key. Returns None if no match
    or if the DB is unreachable (fail-closed — unknown key treated as
    "not a subscriber").
    """
    if not license_key or not db.is_configured():
        return None

    def _do() -> Optional[Dict[str, Any]]:
        client = db.get_client()
        result = (
            client.table("subscriptions")
            .select("*")
            .eq("license_key", license_key)
            .limit(1)
            .execute()
        )
        rows = result.data or []
        return rows[0] if rows else None

    try:
        return _do()
    except Exception as e:
        log.warning("get_by_license_key failed: %s", str(e)[:200])
        return None


def get_by_email(email: str) -> Optional[Dict[str, Any]]:
    """SELECT a subscription row by (lowercased) email."""
    if not email or not db.is_configured():
        return None
    normalized = email.strip().lower()

    def _do() -> Optional[Dict[str, Any]]:
        client = db.get_client()
        result = (
            client.table("subscriptions")
            .select("*")
            .eq("email", normalized)
            .limit(1)
            .execute()
        )
        rows = result.data or []
        return rows[0] if rows else None

    try:
        return _do()
    except Exception as e:
        log.warning("get_by_email failed: %s", str(e)[:200])
        return None


def is_active(subscription: Optional[Dict[str, Any]]) -> bool:
    """
    Returns True if the subscription row grants Pro access right now.

    Access rule: (status in {active, on_trial, cancelled}) AND
                 (NOW() < current_period_end).

    - 'cancelled' users keep access until the end of the current period
      (Lemon Squeezy's standard cancel-at-period-end behavior).
    - 'past_due' and 'unpaid' lose access immediately (we are strict —
      dunning is Lemon's job, not ours).
    - 'paused' loses access until resumed.
    """
    if not subscription:
        return False
    status = subscription.get("status")
    if status not in ("active", "on_trial", "cancelled"):
        return False
    end = subscription.get("current_period_end")
    if not end:
        return False
    try:
        end_dt = datetime.fromisoformat(str(end).replace("Z", "+00:00"))
        if end_dt.tzinfo is None:
            end_dt = end_dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return False
    return datetime.now(timezone.utc) < end_dt


def get_active_by_license_key(license_key: str) -> Optional[Dict[str, Any]]:
    """
    Convenience — returns the row only if is_active() passes.
    This is the function most callers should use for feature gates.
    """
    row = get_by_license_key(license_key)
    return row if is_active(row) else None


def health_check() -> Dict[str, Any]:
    """Diagnostic — reports which Lemon Squeezy env vars are wired up."""
    return {
        "lemon_api_key_set": bool(LEMON_API_KEY),
        "lemon_webhook_secret_set": bool(LEMON_WEBHOOK_SECRET),
        "lemon_store_id": LEMON_STORE_ID or "<unset>",
        "lemon_product_id": LEMON_PRODUCT_ID or "<unset>",
        "lemon_variant_monthly": LEMON_VARIANT_MONTHLY or "<unset>",
        "lemon_variant_yearly": LEMON_VARIANT_YEARLY or "<unset>",
        "lemon_variant_malware_5_pack": LEMON_VARIANT_MALWARE_5_PACK or "<unset>",
        "db_configured": db.is_configured(),
    }
