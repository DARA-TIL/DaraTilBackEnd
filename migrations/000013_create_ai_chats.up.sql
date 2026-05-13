CREATE TABLE IF NOT EXISTS ai_chats (
                                        id BIGSERIAL PRIMARY KEY,

                                        created_at TIMESTAMPTZ NULL,
                                        updated_at TIMESTAMPTZ NULL,
                                        deleted_at TIMESTAMPTZ NULL,

                                        name VARCHAR(255) NOT NULL,
    user_id BIGINT NOT NULL,

    CONSTRAINT fk_ai_chats_user
    FOREIGN KEY (user_id)
    REFERENCES users(id)
    ON UPDATE CASCADE
    ON DELETE CASCADE
    );

CREATE INDEX IF NOT EXISTS idx_ai_chats_deleted_at
    ON ai_chats(deleted_at);

CREATE INDEX IF NOT EXISTS idx_ai_chats_user_id
    ON ai_chats(user_id);


CREATE TABLE IF NOT EXISTS ai_chat_messages (
                                                id BIGSERIAL PRIMARY KEY,

                                                created_at TIMESTAMPTZ NULL,
                                                updated_at TIMESTAMPTZ NULL,
                                                deleted_at TIMESTAMPTZ NULL,

                                                chat_id BIGINT NOT NULL,
                                                message TEXT NOT NULL,
                                                sender_type VARCHAR(20) NOT NULL,

    user_id BIGINT NULL,

    CONSTRAINT fk_ai_chat_messages_chat
    FOREIGN KEY (chat_id)
    REFERENCES ai_chats(id)
    ON UPDATE CASCADE
    ON DELETE CASCADE,

    CONSTRAINT fk_ai_chat_messages_user
    FOREIGN KEY (user_id)
    REFERENCES users(id)
    ON UPDATE CASCADE
    ON DELETE SET NULL
    );

CREATE INDEX IF NOT EXISTS idx_ai_chat_messages_deleted_at
    ON ai_chat_messages(deleted_at);

CREATE INDEX IF NOT EXISTS idx_ai_chat_messages_chat_id
    ON ai_chat_messages(chat_id);

CREATE INDEX IF NOT EXISTS idx_ai_chat_messages_user_id
    ON ai_chat_messages(user_id);

CREATE INDEX IF NOT EXISTS idx_ai_chat_messages_chat_created_at
    ON ai_chat_messages(chat_id, created_at DESC, id DESC);