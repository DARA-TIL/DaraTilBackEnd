package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"

	"gorm.io/gorm"
)

type DictionaryRepository struct {
	db *gorm.DB
}

func NewDictionaryRepository(db *gorm.DB) *DictionaryRepository {
	return &DictionaryRepository{
		db: db,
	}
}

func (d *DictionaryRepository) Create(ctx context.Context, w models.Word) error {
	wGorm := gormMappers.WordToGormModel(w)
	err := d.db.WithContext(ctx).Create(&wGorm).Error
	if err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (d *DictionaryRepository) Update(ctx context.Context, w models.Word) error {
	wGorm := gormMappers.WordToGormModel(w)
	err := d.db.WithContext(ctx).Model(&gormModels.Word{}).Where("id = ?", w.ID).Updates(wGorm).Error
	if err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (d *DictionaryRepository) Delete(ctx context.Context, id uint) error {
	if err := d.db.WithContext(ctx).Unscoped().Where("id = ?", id).Delete(&gormModels.Word{}).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (d *DictionaryRepository) GetAll(ctx context.Context) ([]models.Word, error) {
	var words []gormModels.Word
	err := d.db.WithContext(ctx).Find(&words).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	domWords := gormMappers.GormWordsToDomainModel(words)
	return domWords, nil
}

func (d *DictionaryRepository) GetExactWord(ctx context.Context, word string, block string) (*models.Word, error) {
	var dbWord gormModels.Word
	err := d.db.WithContext(ctx).Where("original_word = ? AND used_block = ?", word, block).First(&dbWord).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	domWord := gormMappers.GormWordToDomainModel(dbWord)
	return &domWord, nil

}

func (d *DictionaryRepository) GetWord(ctx context.Context, word string) ([]models.Word, error) {
	var words []gormModels.Word
	err := d.db.WithContext(ctx).Where("original_word = ?", word).Find(&words).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	domWords := gormMappers.GormWordsToDomainModel(words)
	return domWords, nil
}
func (d *DictionaryRepository) GetByID(ctx context.Context, id uint) (*models.Word, error) {
	var dbWord gormModels.Word
	err := d.db.WithContext(ctx).First(&dbWord, id).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	domWord := gormMappers.GormWordToDomainModel(dbWord)
	return &domWord, nil
}
