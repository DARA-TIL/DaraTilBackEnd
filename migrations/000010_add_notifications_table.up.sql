CREATE TABLE IF NOT EXISTS notifications (
                                             id BIGSERIAL PRIMARY KEY,
                                             created_at TIMESTAMPTZ,
                                             updated_at TIMESTAMPTZ,
                                             deleted_at TIMESTAMPTZ,

                                             title TEXT NOT NULL,
                                             message TEXT NOT NULL,
                                             type VARCHAR(50) NOT NULL,

    scope VARCHAR(50) NOT NULL,
    user_id BIGINT NULL,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT fk_notifications_user
    FOREIGN KEY (user_id)
    REFERENCES users(id)
    ON UPDATE CASCADE
    ON DELETE SET NULL
    );

CREATE INDEX IF NOT EXISTS idx_notifications_deleted_at
    ON notifications(deleted_at);

CREATE INDEX IF NOT EXISTS idx_notifications_user_id
    ON notifications(user_id);

CREATE INDEX IF NOT EXISTS idx_notifications_scope
    ON notifications(scope);

CREATE INDEX IF NOT EXISTS idx_notifications_type
    ON notifications(type);

CREATE INDEX IF NOT EXISTS idx_notifications_is_active
    ON notifications(is_active);

CREATE TABLE IF NOT EXISTS notification_reads (
                                                  id BIGSERIAL PRIMARY KEY,
                                                  created_at TIMESTAMPTZ,
                                                  updated_at TIMESTAMPTZ,
                                                  deleted_at TIMESTAMPTZ,

                                                  notification_id BIGINT NOT NULL,
                                                  user_id BIGINT NOT NULL,

                                                  read_at TIMESTAMPTZ,

                                                  CONSTRAINT fk_notification_reads_notification
                                                  FOREIGN KEY (notification_id)
    REFERENCES notifications(id)
    ON UPDATE CASCADE
    ON DELETE CASCADE,

    CONSTRAINT fk_notification_reads_user
    FOREIGN KEY (user_id)
    REFERENCES users(id)
    ON UPDATE CASCADE
    ON DELETE CASCADE
    );

CREATE INDEX IF NOT EXISTS idx_notification_reads_deleted_at
    ON notification_reads(deleted_at);

CREATE INDEX IF NOT EXISTS idx_notification_reads_notification_id
    ON notification_reads(notification_id);

CREATE INDEX IF NOT EXISTS idx_notification_reads_user_id
    ON notification_reads(user_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_notification_reads_unique
    ON notification_reads(notification_id, user_id);