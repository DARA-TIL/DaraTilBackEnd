CREATE TABLE IF NOT EXISTS daily_action_usages (
                                                   id BIGSERIAL PRIMARY KEY,

                                                   user_id BIGINT NOT NULL,

                                                   action VARCHAR(100) NOT NULL,

    usage_date DATE NOT NULL,

    count INTEGER NOT NULL DEFAULT 0,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_daily_action_usage_user_action_date
    UNIQUE (user_id, action, usage_date)
    );

CREATE INDEX IF NOT EXISTS idx_daily_action_usages_user_id
    ON daily_action_usages (user_id);

CREATE INDEX IF NOT EXISTS idx_daily_action_usages_action
    ON daily_action_usages (action);

CREATE INDEX IF NOT EXISTS idx_daily_action_usages_usage_date
    ON daily_action_usages (usage_date);