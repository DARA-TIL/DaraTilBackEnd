BEGIN;

-- user_profiles
CREATE TABLE user_profiles (
                               id BIGSERIAL PRIMARY KEY,
                               created_at TIMESTAMPTZ,
                               updated_at TIMESTAMPTZ,
                               deleted_at TIMESTAMPTZ,

                               user_id BIGINT NOT NULL UNIQUE,
                               lessons_completed BIGINT NOT NULL DEFAULT 0,
                               words_learned BIGINT NOT NULL DEFAULT 0,

                               CONSTRAINT fk_user_profiles_user
                                   FOREIGN KEY (user_id) REFERENCES users(id)
                                       ON UPDATE CASCADE
                                       ON DELETE CASCADE
);

CREATE INDEX idx_user_profiles_deleted_at ON user_profiles(deleted_at);

-- pinned_achievements
CREATE TABLE pinned_achievements (
                                     id BIGSERIAL PRIMARY KEY,
                                     created_at TIMESTAMPTZ,
                                     updated_at TIMESTAMPTZ,
                                     deleted_at TIMESTAMPTZ,

                                     achievement_id BIGINT NOT NULL,
                                     user_id BIGINT NOT NULL,

                                     CONSTRAINT fk_pinned_achievements_achievement
                                         FOREIGN KEY (achievement_id) REFERENCES achievements(id)
                                             ON UPDATE CASCADE
                                             ON DELETE CASCADE,

                                     CONSTRAINT fk_pinned_achievements_user
                                         FOREIGN KEY (user_id) REFERENCES users(id)
                                             ON UPDATE CASCADE
                                             ON DELETE CASCADE
);

CREATE INDEX idx_pinned_achievements_deleted_at ON pinned_achievements(deleted_at);
CREATE INDEX idx_pinned_achievements_user_id ON pinned_achievements(user_id);
CREATE INDEX idx_pinned_achievements_achievement_id ON pinned_achievements(achievement_id);

-- чтобы один и тот же achievement не был pinned дважды у одного user
CREATE UNIQUE INDEX user_pinned_achievement_idx
    ON pinned_achievements(user_id, achievement_id);

COMMIT;