CREATE TABLE time_events (
                             id BIGSERIAL PRIMARY KEY,

                             created_at TIMESTAMPTZ,
                             updated_at TIMESTAMPTZ,
                             deleted_at TIMESTAMPTZ,

                             name VARCHAR(255) NOT NULL,
                             description TEXT,

                             reward_first BIGINT NOT NULL DEFAULT 0,
                             reward_second BIGINT NOT NULL DEFAULT 0,
                             reward_third BIGINT NOT NULL DEFAULT 0,

                             event_type VARCHAR(100) NOT NULL,

                             duration BIGINT NOT NULL,

                             start_date TIMESTAMPTZ NOT NULL,
                             end_date TIMESTAMPTZ NOT NULL,

                             status VARCHAR(50) NOT NULL DEFAULT 'waiting'
);

CREATE INDEX idx_time_events_deleted_at
    ON time_events(deleted_at);

CREATE TABLE time_event_participants (
                                         id BIGSERIAL PRIMARY KEY,

                                         user_id BIGINT NOT NULL,
                                         time_event_id BIGINT NOT NULL,

                                         count INT NOT NULL DEFAULT 0,
                                         is_active BOOLEAN NOT NULL DEFAULT TRUE,
                                         place INT NOT NULL DEFAULT 0,

                                         CONSTRAINT fk_time_event_participants_user
                                             FOREIGN KEY (user_id)
                                                 REFERENCES users(id)
                                                 ON UPDATE CASCADE
                                                 ON DELETE CASCADE,

                                         CONSTRAINT fk_time_event_participants_time_event
                                             FOREIGN KEY (time_event_id)
                                                 REFERENCES time_events(id)
                                                 ON UPDATE CASCADE
                                                 ON DELETE CASCADE
);