CREATE TABLE words (
                       id BIGSERIAL PRIMARY KEY,
                       created_at TIMESTAMPTZ,
                       updated_at TIMESTAMPTZ,
                       deleted_at TIMESTAMPTZ,

                       original_word TEXT NOT NULL,
                       context TEXT NOT NULL,
                       word_translations JSONB NOT NULL,
                       word_explaining_translations JSONB NOT NULL
);

CREATE UNIQUE INDEX word_context_idx
    ON words (original_word, context);

CREATE INDEX idx_words_deleted_at
    ON words (deleted_at);
