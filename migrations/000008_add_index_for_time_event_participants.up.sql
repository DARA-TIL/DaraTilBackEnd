CREATE INDEX IF NOT EXISTS idx_time_event_participants_user_id
    ON time_event_participants(user_id);

CREATE INDEX IF NOT EXISTS idx_time_event_participants_time_event_id
    ON time_event_participants(time_event_id);


-- optional: one user can participate in one event only once
CREATE UNIQUE INDEX IF NOT EXISTS idx_time_event_participants_user_event_unique
    ON time_event_participants(user_id, time_event_id);