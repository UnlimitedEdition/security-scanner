-- Track device activations per license key (max 5 devices)
CREATE TABLE IF NOT EXISTS license_activations (
    id            BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    fingerprint   TEXT NOT NULL,
    user_agent    TEXT,
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_activation_sub_fp
    ON license_activations (subscription_id, fingerprint);

CREATE INDEX IF NOT EXISTS idx_activation_sub
    ON license_activations (subscription_id);
