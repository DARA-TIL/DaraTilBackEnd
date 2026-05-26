CREATE TABLE IF NOT EXISTS payments (
                                        id BIGSERIAL PRIMARY KEY,

                                        user_id BIGINT NOT NULL,
                                        plan_id BIGINT NOT NULL,

                                        amount INTEGER NOT NULL,
                                        currency VARCHAR(10) NOT NULL DEFAULT 'KZT',

    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    provider VARCHAR(50) NOT NULL,

    provider_payment_id VARCHAR(255),
    payment_url TEXT,

    paid_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_payments_plan
    FOREIGN KEY (plan_id)
    REFERENCES subscription_plans (id)
    ON UPDATE CASCADE
    ON DELETE RESTRICT,

    CONSTRAINT check_payment_status
    CHECK (status IN ('pending', 'paid', 'failed', 'expired')),

    CONSTRAINT check_payment_amount
    CHECK (amount >= 0)
    );

CREATE INDEX IF NOT EXISTS idx_payments_user_id
    ON payments (user_id);

CREATE INDEX IF NOT EXISTS idx_payments_plan_id
    ON payments (plan_id);

CREATE INDEX IF NOT EXISTS idx_payments_status
    ON payments (status);

CREATE INDEX IF NOT EXISTS idx_payments_provider
    ON payments (provider);

CREATE INDEX IF NOT EXISTS idx_payments_provider_payment_id
    ON payments (provider_payment_id);

CREATE INDEX IF NOT EXISTS idx_payments_paid_at
    ON payments (paid_at);