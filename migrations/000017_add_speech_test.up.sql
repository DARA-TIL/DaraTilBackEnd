CREATE TABLE speech_tests (
                              id BIGSERIAL PRIMARY KEY,
                              created_at TIMESTAMPTZ,
                              updated_at TIMESTAMPTZ,
                              deleted_at TIMESTAMPTZ,

                              kz_text TEXT NOT NULL,
                              ru_text TEXT NOT NULL,
                              en_text TEXT NOT NULL,
                              difficulty VARCHAR(20) NOT NULL
);

CREATE INDEX idx_speech_tests_deleted_at
    ON speech_tests (deleted_at);

CREATE INDEX idx_speech_tests_difficulty
    ON speech_tests (difficulty);


CREATE TABLE speech_test_sessions (
                                      id BIGSERIAL PRIMARY KEY,
                                      created_at TIMESTAMPTZ,
                                      updated_at TIMESTAMPTZ,
                                      deleted_at TIMESTAMPTZ,

                                      user_id BIGINT NOT NULL,
                                      correct_count INTEGER NOT NULL DEFAULT 0,
                                      is_ended BOOLEAN NOT NULL DEFAULT FALSE,

                                      CONSTRAINT fk_speech_test_sessions_user
                                          FOREIGN KEY (user_id)
                                              REFERENCES users (id)
                                              ON UPDATE CASCADE
                                              ON DELETE CASCADE
);

CREATE INDEX idx_speech_test_sessions_deleted_at
    ON speech_test_sessions (deleted_at);

CREATE INDEX idx_speech_test_sessions_user_id
    ON speech_test_sessions (user_id);

CREATE INDEX idx_speech_test_sessions_user_active
    ON speech_test_sessions (user_id, is_ended);


CREATE TABLE speech_test_session_tests (
                                           id BIGSERIAL PRIMARY KEY,
                                           created_at TIMESTAMPTZ,
                                           updated_at TIMESTAMPTZ,
                                           deleted_at TIMESTAMPTZ,

                                           session_id BIGINT NOT NULL,
                                           test_id BIGINT NOT NULL,

                                           is_shown BOOLEAN NOT NULL DEFAULT FALSE,
                                           is_answered BOOLEAN NOT NULL DEFAULT FALSE,
                                           is_correct BOOLEAN NOT NULL DEFAULT FALSE,

                                           CONSTRAINT fk_speech_test_session_tests_session
                                               FOREIGN KEY (session_id)
                                                   REFERENCES speech_test_sessions (id)
                                                   ON UPDATE CASCADE
                                                   ON DELETE CASCADE,

                                           CONSTRAINT fk_speech_test_session_tests_test
                                               FOREIGN KEY (test_id)
                                                   REFERENCES speech_tests (id)
                                                   ON UPDATE CASCADE
                                                   ON DELETE CASCADE
);

CREATE INDEX idx_speech_test_session_tests_deleted_at
    ON speech_test_session_tests (deleted_at);

CREATE INDEX idx_speech_test_session_tests_session_id
    ON speech_test_session_tests (session_id);

CREATE INDEX idx_speech_test_session_tests_test_id
    ON speech_test_session_tests (test_id);

CREATE INDEX idx_speech_test_session_tests_session_answered
    ON speech_test_session_tests (session_id, is_answered);

CREATE INDEX idx_speech_test_session_tests_session_shown
    ON speech_test_session_tests (session_id, is_shown);

CREATE UNIQUE INDEX idx_speech_test_session_tests_unique_session_test
    ON speech_test_session_tests (session_id, test_id)
    WHERE deleted_at IS NULL;
