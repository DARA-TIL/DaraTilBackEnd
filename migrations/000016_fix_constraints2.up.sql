ALTER TABLE folklore_likes
DROP CONSTRAINT IF EXISTS fk_folklore_likes_user;

ALTER TABLE folklore_likes
    ADD CONSTRAINT fk_folklore_likes_user
        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON UPDATE CASCADE
            ON DELETE CASCADE;
ALTER TABLE folklore_likes
DROP CONSTRAINT IF EXISTS fk_folklore_likes_folklore;

ALTER TABLE folklore_likes
    ADD CONSTRAINT fk_folklore_likes_folklore
        FOREIGN KEY (folklore_id)
            REFERENCES folklores(id)
            ON UPDATE CASCADE
            ON DELETE CASCADE;