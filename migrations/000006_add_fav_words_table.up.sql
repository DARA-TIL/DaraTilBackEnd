CREATE TABLE favorite_words (
                                user_id BIGINT NOT NULL,
                                word_id BIGINT NOT NULL,
                                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

                                CONSTRAINT pk_favorite_words PRIMARY KEY (user_id, word_id),

                                CONSTRAINT fk_favorite_words_user
                                    FOREIGN KEY (user_id)
                                        REFERENCES users(id)
                                        ON DELETE CASCADE,

                                CONSTRAINT fk_favorite_words_word
                                    FOREIGN KEY (word_id)
                                        REFERENCES words(id)
                                        ON DELETE CASCADE
);