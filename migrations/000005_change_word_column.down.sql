ALTER TABLE words RENAME COLUMN used_block TO context;

DROP INDEX IF EXISTS word_block_idx;

CREATE UNIQUE INDEX word_context_idx
    ON words (original_word, context);