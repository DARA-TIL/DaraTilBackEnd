CREATE TABLE IF NOT EXISTS subscription_plans (
                                                  id BIGSERIAL PRIMARY KEY,

                                                  name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,

    price INTEGER NOT NULL,
    duration_days INTEGER NOT NULL,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

CREATE INDEX IF NOT EXISTS idx_subscription_plans_is_active
    ON subscription_plans (is_active);
ALTER TABLE subscription_plans
    ADD CONSTRAINT check_subscription_plan_price
        CHECK (price >= 0);

ALTER TABLE subscription_plans
    ADD CONSTRAINT check_subscription_plan_duration_days
        CHECK (duration_days > 0);

CREATE TABLE IF NOT EXISTS subscriptions (
                                             id BIGSERIAL PRIMARY KEY,

                                             user_id BIGINT NOT NULL,

                                             status VARCHAR(20) NOT NULL DEFAULT 'active',

    plan_id BIGINT NOT NULL,

    active_until TIMESTAMPTZ NOT NULL,
    cancelled_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_subscriptions_plan
    FOREIGN KEY (plan_id)
    REFERENCES subscription_plans (id)
    ON UPDATE CASCADE
    ON DELETE RESTRICT
    );

CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id
    ON subscriptions (user_id);

CREATE INDEX IF NOT EXISTS idx_subscriptions_status
    ON subscriptions (status);

CREATE INDEX IF NOT EXISTS idx_subscriptions_plan_id
    ON subscriptions (plan_id);

CREATE INDEX IF NOT EXISTS idx_subscriptions_active_until
    ON subscriptions (active_until);

CREATE INDEX IF NOT EXISTS idx_subscriptions_cancelled_at
    ON subscriptions (cancelled_at);

ALTER TABLE subscriptions
    ADD CONSTRAINT check_subscription_status
        CHECK (status IN ('active', 'expired', 'cancelled'));