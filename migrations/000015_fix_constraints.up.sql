ALTER TABLE tests
DROP CONSTRAINT IF EXISTS fk_lessons_test;

ALTER TABLE tests
    ADD CONSTRAINT fk_lessons_test
        FOREIGN KEY (lesson_id)
            REFERENCES lessons(id)
            ON UPDATE CASCADE
            ON DELETE CASCADE;

ALTER TABLE region_slang_translations
DROP CONSTRAINT IF EXISTS fk_region_slangs_translations;

ALTER TABLE region_slang_translations
    ADD CONSTRAINT fk_region_slangs_translations
        FOREIGN KEY (region_slang_id)
            REFERENCES region_slangs(id)
            ON UPDATE CASCADE
            ON DELETE CASCADE;

ALTER TABLE region_traditions_translations
DROP CONSTRAINT IF EXISTS fk_region_traditions_translations;

ALTER TABLE region_traditions_translations
    ADD CONSTRAINT fk_region_traditions_translations
        FOREIGN KEY (region_traditions_id)
            REFERENCES region_traditions(id)
            ON UPDATE CASCADE
            ON DELETE CASCADE;
