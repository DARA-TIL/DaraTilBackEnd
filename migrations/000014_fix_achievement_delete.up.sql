ALTER TABLE user_achievements
DROP CONSTRAINT IF EXISTS fk_achievements_user_achievements;

ALTER TABLE user_achievements
    ADD CONSTRAINT fk_achievements_user_achievements
        FOREIGN KEY (achievement_id)
            REFERENCES achievements(id)
            ON UPDATE CASCADE
            ON DELETE CASCADE;