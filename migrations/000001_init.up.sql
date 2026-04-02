BEGIN;

-- users
CREATE TABLE users (
                       id BIGSERIAL PRIMARY KEY,
                       created_at TIMESTAMPTZ,
                       updated_at TIMESTAMPTZ,
                       deleted_at TIMESTAMPTZ,

                       username TEXT NOT NULL UNIQUE,
                       email TEXT NOT NULL UNIQUE,
                       password TEXT NOT NULL,
                       avatar TEXT,
                       role TEXT NOT NULL,
                       auth_provider TEXT NOT NULL
);

CREATE INDEX idx_users_deleted_at ON users(deleted_at);

-- user_progresses
CREATE TABLE user_progresses (
                                 id BIGSERIAL PRIMARY KEY,
                                 created_at TIMESTAMPTZ,
                                 updated_at TIMESTAMPTZ,
                                 deleted_at TIMESTAMPTZ,

                                 user_id BIGINT NOT NULL,
                                 level BIGINT DEFAULT 1,
                                 xp_total BIGINT DEFAULT 0,
                                 xp_for_next_level BIGINT DEFAULT 100,

                                 CONSTRAINT fk_user_progresses_user
                                     FOREIGN KEY (user_id) REFERENCES users(id)
                                         ON UPDATE CASCADE
                                         ON DELETE CASCADE
);

CREATE INDEX idx_user_progresses_deleted_at ON user_progresses(deleted_at);

-- streaks
CREATE TABLE streaks (
                         id BIGSERIAL PRIMARY KEY,
                         created_at TIMESTAMPTZ,
                         updated_at TIMESTAMPTZ,
                         deleted_at TIMESTAMPTZ,

                         user_id BIGINT UNIQUE,
                         current_streak BIGINT NOT NULL DEFAULT 0,
                         longest_streak BIGINT NOT NULL DEFAULT 0,
                         last_activity DATE,

                         CONSTRAINT fk_streaks_user
                             FOREIGN KEY (user_id) REFERENCES users(id)
                                 ON UPDATE CASCADE
                                 ON DELETE CASCADE
);

CREATE INDEX idx_streaks_deleted_at ON streaks(deleted_at);

-- tokens
CREATE TABLE tokens (
                        id BIGSERIAL PRIMARY KEY,
                        created_at TIMESTAMPTZ,
                        updated_at TIMESTAMPTZ,
                        deleted_at TIMESTAMPTZ,

                        user_id BIGINT NOT NULL,
                        refresh_token_hash TEXT NOT NULL,
                        device TEXT NOT NULL,
                        ip_address TEXT NOT NULL,
                        user_agent TEXT NOT NULL,
                        is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
                        expires TIMESTAMPTZ NOT NULL,
                        last_used TIMESTAMPTZ,

                        CONSTRAINT fk_tokens_user
                            FOREIGN KEY (user_id) REFERENCES users(id)
                                ON UPDATE CASCADE
                                ON DELETE CASCADE
);

CREATE INDEX idx_tokens_deleted_at ON tokens(deleted_at);
CREATE INDEX idx_tokens_user_id ON tokens(user_id);
CREATE INDEX idx_tokens_refresh_token_hash ON tokens(refresh_token_hash);

-- folklores
CREATE TABLE folklores (
                           id BIGSERIAL PRIMARY KEY,
                           created_at TIMESTAMPTZ,
                           updated_at TIMESTAMPTZ,
                           deleted_at TIMESTAMPTZ,

                           type TEXT NOT NULL,
                           author TEXT NOT NULL,
                           region TEXT NOT NULL,
                           content TEXT,
                           name TEXT,
                           media_url TEXT,
                           image_url TEXT,
                           likes_count BIGINT DEFAULT 0
);

CREATE INDEX idx_folklores_deleted_at ON folklores(deleted_at);

-- folklore_translations
CREATE TABLE folklore_translations (
                                       id BIGSERIAL PRIMARY KEY,
                                       created_at TIMESTAMPTZ,
                                       updated_at TIMESTAMPTZ,
                                       deleted_at TIMESTAMPTZ,

                                       folklore_id BIGINT NOT NULL,
                                       language TEXT NOT NULL,
                                       name TEXT NOT NULL,
                                       content TEXT NOT NULL,
                                       explanation TEXT NOT NULL,

                                       CONSTRAINT fk_folklore_translations_folklore
                                           FOREIGN KEY (folklore_id) REFERENCES folklores(id)
                                               ON DELETE CASCADE
);

CREATE INDEX idx_folklore_translations_deleted_at ON folklore_translations(deleted_at);
CREATE INDEX idx_folklore_translations_folklore_id ON folklore_translations(folklore_id);

-- folklore_likes
CREATE TABLE folklore_likes (
                                id BIGSERIAL PRIMARY KEY,
                                created_at TIMESTAMPTZ,
                                updated_at TIMESTAMPTZ,
                                deleted_at TIMESTAMPTZ,

                                user_id BIGINT NOT NULL,
                                folklore_id BIGINT NOT NULL,

                                CONSTRAINT fk_folklore_likes_user
                                    FOREIGN KEY (user_id) REFERENCES users(id)
                                        ON DELETE CASCADE,

                                CONSTRAINT fk_folklore_likes_folklore
                                    FOREIGN KEY (folklore_id) REFERENCES folklores(id)
                                        ON DELETE CASCADE
);

CREATE INDEX idx_folklore_likes_deleted_at ON folklore_likes(deleted_at);
CREATE UNIQUE INDEX user_folklore_idx ON folklore_likes(user_id, folklore_id);

-- lessons
CREATE TABLE lessons (
                         id BIGSERIAL PRIMARY KEY,
                         created_at TIMESTAMPTZ,
                         updated_at TIMESTAMPTZ,
                         deleted_at TIMESTAMPTZ,

                         name TEXT NOT NULL,
                         description TEXT NOT NULL,
                         image_url TEXT,
                         author TEXT NOT NULL,
                         reward BIGINT NOT NULL,
                         required_level BIGINT NOT NULL
);

CREATE INDEX idx_lessons_deleted_at ON lessons(deleted_at);

-- lesson_blocks
CREATE TABLE lesson_blocks (
                               id BIGSERIAL PRIMARY KEY,
                               created_at TIMESTAMPTZ,
                               updated_at TIMESTAMPTZ,
                               deleted_at TIMESTAMPTZ,

                               name TEXT NOT NULL,
                               content_type TEXT NOT NULL,
                               content_url TEXT,
                               content_text TEXT,
                               lesson_id BIGINT NOT NULL,
                               position BIGINT NOT NULL,

                               CONSTRAINT fk_lesson_blocks_lesson
                                   FOREIGN KEY (lesson_id) REFERENCES lessons(id)
                                       ON UPDATE CASCADE
                                       ON DELETE CASCADE
);

CREATE INDEX idx_lesson_blocks_deleted_at ON lesson_blocks(deleted_at);
CREATE INDEX idx_lesson_blocks_lesson_id ON lesson_blocks(lesson_id);

-- tests
CREATE TABLE tests (
                       id BIGSERIAL PRIMARY KEY,
                       created_at TIMESTAMPTZ,
                       updated_at TIMESTAMPTZ,
                       deleted_at TIMESTAMPTZ,

                       lesson_id BIGINT NOT NULL UNIQUE,

                       CONSTRAINT fk_tests_lesson
                           FOREIGN KEY (lesson_id) REFERENCES lessons(id)
                               ON UPDATE CASCADE
                               ON DELETE CASCADE
);

CREATE INDEX idx_tests_deleted_at ON tests(deleted_at);

-- questions
CREATE TABLE questions (
                           id BIGSERIAL PRIMARY KEY,
                           created_at TIMESTAMPTZ,
                           updated_at TIMESTAMPTZ,
                           deleted_at TIMESTAMPTZ,

                           test_id BIGINT NOT NULL,
                           text TEXT NOT NULL,

                           CONSTRAINT fk_questions_test
                               FOREIGN KEY (test_id) REFERENCES tests(id)
                                   ON UPDATE CASCADE
                                   ON DELETE CASCADE
);

CREATE INDEX idx_questions_deleted_at ON questions(deleted_at);
CREATE INDEX idx_questions_test_id ON questions(test_id);

-- question_options
CREATE TABLE question_options (
                                  id BIGSERIAL PRIMARY KEY,
                                  created_at TIMESTAMPTZ,
                                  updated_at TIMESTAMPTZ,
                                  deleted_at TIMESTAMPTZ,

                                  question_id BIGINT NOT NULL,
                                  is_correct BOOLEAN DEFAULT FALSE,
                                  text TEXT,

                                  CONSTRAINT fk_question_options_question
                                      FOREIGN KEY (question_id) REFERENCES questions(id)
                                          ON UPDATE CASCADE
                                          ON DELETE CASCADE
);

CREATE INDEX idx_question_options_deleted_at ON question_options(deleted_at);
CREATE INDEX idx_question_options_question_id ON question_options(question_id);

-- lesson_results
CREATE TABLE lesson_results (
                                id BIGSERIAL PRIMARY KEY,
                                created_at TIMESTAMPTZ,
                                updated_at TIMESTAMPTZ,
                                deleted_at TIMESTAMPTZ,

                                lesson_id BIGINT NOT NULL,
                                user_id BIGINT NOT NULL,
                                test_id BIGINT NOT NULL,
                                result BIGINT NOT NULL,
                                pass BOOLEAN NOT NULL,
                                pass_time TIMESTAMPTZ NOT NULL,

                                CONSTRAINT fk_lesson_results_lesson
                                    FOREIGN KEY (lesson_id) REFERENCES lessons(id),

                                CONSTRAINT fk_lesson_results_user
                                    FOREIGN KEY (user_id) REFERENCES users(id),

                                CONSTRAINT fk_lesson_results_test
                                    FOREIGN KEY (test_id) REFERENCES tests(id)
);

CREATE INDEX idx_lesson_results_deleted_at ON lesson_results(deleted_at);
CREATE INDEX idx_lesson_results_user_id ON lesson_results(user_id);
CREATE INDEX idx_lesson_results_lesson_id ON lesson_results(lesson_id);
CREATE INDEX idx_lesson_results_test_id ON lesson_results(test_id);

-- user_activities
CREATE TABLE user_activities (
                                 id BIGSERIAL PRIMARY KEY,
                                 created_at TIMESTAMPTZ,
                                 updated_at TIMESTAMPTZ,
                                 deleted_at TIMESTAMPTZ,

                                 user_id BIGINT NOT NULL,
                                 action TEXT NOT NULL,
                                 entity_type TEXT NOT NULL,
                                 entity_id BIGINT NOT NULL,

                                 CONSTRAINT fk_user_activities_user
                                     FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_user_activities_deleted_at ON user_activities(deleted_at);
CREATE INDEX idx_user_activities_user_id ON user_activities(user_id);

-- regions
CREATE TABLE regions (
                         id BIGSERIAL PRIMARY KEY,
                         created_at TIMESTAMPTZ,
                         updated_at TIMESTAMPTZ,
                         deleted_at TIMESTAMPTZ,

                         required_level BIGINT,
                         code TEXT UNIQUE,
                         kind TEXT,
                         is_active BOOLEAN DEFAULT TRUE,
                         image_url TEXT
);

CREATE INDEX idx_regions_deleted_at ON regions(deleted_at);

-- region_translations
CREATE TABLE region_translations (
                                     id BIGSERIAL PRIMARY KEY,
                                     created_at TIMESTAMPTZ,
                                     updated_at TIMESTAMPTZ,
                                     deleted_at TIMESTAMPTZ,

                                     region_id BIGINT,
                                     language TEXT,
                                     name TEXT,
                                     description TEXT,

                                     CONSTRAINT fk_region_translations_region
                                         FOREIGN KEY (region_id) REFERENCES regions(id)
                                             ON UPDATE CASCADE
                                             ON DELETE CASCADE
);

CREATE INDEX idx_region_translations_deleted_at ON region_translations(deleted_at);
CREATE INDEX idx_region_translations_region_id ON region_translations(region_id);

-- region_slangs
CREATE TABLE region_slangs (
                               id BIGSERIAL PRIMARY KEY,
                               created_at TIMESTAMPTZ,
                               updated_at TIMESTAMPTZ,
                               deleted_at TIMESTAMPTZ,

                               region_id BIGINT,

                               CONSTRAINT fk_region_slangs_region
                                   FOREIGN KEY (region_id) REFERENCES regions(id)
                                       ON UPDATE CASCADE
                                       ON DELETE CASCADE
);

CREATE INDEX idx_region_slangs_deleted_at ON region_slangs(deleted_at);
CREATE INDEX idx_region_slangs_region_id ON region_slangs(region_id);

-- region_slang_translations
CREATE TABLE region_slang_translations (
                                           id BIGSERIAL PRIMARY KEY,
                                           created_at TIMESTAMPTZ,
                                           updated_at TIMESTAMPTZ,
                                           deleted_at TIMESTAMPTZ,

                                           region_slang_id BIGINT,
                                           language TEXT,
                                           word TEXT,
                                           description TEXT,
                                           pronounce_url TEXT,

                                           CONSTRAINT fk_region_slang_translations_region_slang
                                               FOREIGN KEY (region_slang_id) REFERENCES region_slangs(id)
                                                   ON UPDATE CASCADE
                                                   ON DELETE CASCADE
);

CREATE INDEX idx_region_slang_translations_deleted_at ON region_slang_translations(deleted_at);
CREATE INDEX idx_region_slang_translations_region_slang_id ON region_slang_translations(region_slang_id);

-- region_traditions
CREATE TABLE region_traditions (
                                   id BIGSERIAL PRIMARY KEY,
                                   created_at TIMESTAMPTZ,
                                   updated_at TIMESTAMPTZ,
                                   deleted_at TIMESTAMPTZ,

                                   region_id BIGINT,

                                   CONSTRAINT fk_region_traditions_region
                                       FOREIGN KEY (region_id) REFERENCES regions(id)
                                           ON UPDATE CASCADE
                                           ON DELETE CASCADE
);

CREATE INDEX idx_region_traditions_deleted_at ON region_traditions(deleted_at);
CREATE INDEX idx_region_traditions_region_id ON region_traditions(region_id);

-- region_traditions_translations
CREATE TABLE region_traditions_translations (
                                                id BIGSERIAL PRIMARY KEY,
                                                created_at TIMESTAMPTZ,
                                                updated_at TIMESTAMPTZ,
                                                deleted_at TIMESTAMPTZ,

                                                region_traditions_id BIGINT,
                                                language TEXT,
                                                name TEXT,
                                                description TEXT,

                                                CONSTRAINT fk_region_traditions_translations_region_traditions
                                                    FOREIGN KEY (region_traditions_id) REFERENCES region_traditions(id)
                                                        ON UPDATE CASCADE
                                                        ON DELETE CASCADE
);

CREATE INDEX idx_region_traditions_translations_deleted_at ON region_traditions_translations(deleted_at);
CREATE INDEX idx_region_traditions_translations_region_traditions_id ON region_traditions_translations(region_traditions_id);

-- achievements
CREATE TABLE achievements (
                              id BIGSERIAL PRIMARY KEY,
                              created_at TIMESTAMPTZ,
                              updated_at TIMESTAMPTZ,
                              deleted_at TIMESTAMPTZ,

                              name TEXT,
                              description TEXT,
                              action TEXT,
                              quantity BIGINT,
                              icon_url TEXT
);

CREATE INDEX idx_achievements_deleted_at ON achievements(deleted_at);

-- user_achievements
CREATE TABLE user_achievements (
                                   id BIGSERIAL PRIMARY KEY,
                                   user_id BIGINT NOT NULL,
                                   achievement_id BIGINT NOT NULL,
                                   quantity BIGINT DEFAULT 0,
                                   achieved BOOLEAN DEFAULT FALSE,

                                   CONSTRAINT fk_user_achievements_user
                                       FOREIGN KEY (user_id) REFERENCES users(id)
                                           ON UPDATE CASCADE
                                           ON DELETE CASCADE,

                                   CONSTRAINT fk_user_achievements_achievement
                                       FOREIGN KEY (achievement_id) REFERENCES achievements(id)
                                           ON UPDATE CASCADE
                                           ON DELETE CASCADE
);

CREATE UNIQUE INDEX user_achievement_idx
    ON user_achievements(user_id, achievement_id);

-- action_rules
CREATE TABLE action_rules (
                              id BIGSERIAL PRIMARY KEY,
                              action TEXT UNIQUE,
                              rules JSONB
);

COMMIT;