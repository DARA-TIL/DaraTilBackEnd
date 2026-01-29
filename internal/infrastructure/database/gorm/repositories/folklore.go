package repositories

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/utils"
	"context"
	"errors"

	"gorm.io/gorm"
)

type FolkloreRepository struct {
	db *gorm.DB
}

func NewFolkloreRepository(db *gorm.DB) *FolkloreRepository {
	return &FolkloreRepository{
		db: db,
	}
}

func (f FolkloreRepository) Create(ctx context.Context, folklore models.Folklore) (*models.Folklore, error) {
	folkloreGorm := gormMappers.FolkloreToGormModel(folklore)
	err := f.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&folkloreGorm).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, utils.ErrHandler(err)
	}
	folklore = gormMappers.GormFolkloreToDomainModel(folkloreGorm)
	return &folklore, nil
}

func (f FolkloreRepository) GetByID(ctx context.Context, id int) (*models.Folklore, error) {
	var folklore gormModels.Folklore
	if err := f.db.WithContext(ctx).Preload("Translations").First(&folklore, id).Error; err != nil {
		return nil, utils.ErrHandler(err)
	}
	domainFolklore := gormMappers.GormFolkloreToDomainModel(folklore)
	return &domainFolklore, nil
}

func (f FolkloreRepository) GetAll(ctx context.Context) ([]models.Folklore, error) {
	var folklores []gormModels.Folklore
	if err := f.db.WithContext(ctx).Preload("Translations").Find(&folklores).Error; err != nil {
		return nil, utils.ErrHandler(err)
	}
	domainFolklore := make([]models.Folklore, 0)
	for _, folklore := range folklores {
		domF := gormMappers.GormFolkloreToDomainModel(folklore)
		domainFolklore = append(domainFolklore, domF)
	}
	return domainFolklore, nil
}

func (f FolkloreRepository) Update(ctx context.Context, id int, fields models.UpdatableFolkloreFields) (*models.Folklore, error) {
	updates := make(map[string]any)
	if fields.Name != nil {
		updates["name"] = *fields.Name
	}
	if fields.Content != nil {
		updates["content"] = *fields.Content
	}
	if fields.ImageUrl != nil {
		updates["image_url"] = *fields.ImageUrl
	}
	if fields.Author != nil {
		updates["author"] = *fields.Author
	}
	if fields.MediaUrl != nil {
		updates["media_url"] = *fields.MediaUrl
	}
	if fields.Region != nil {
		updates["region"] = *fields.Region
	}
	if fields.Type != nil {
		updates["type"] = *fields.Type
	}
	err := f.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&gormModels.Folklore{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			return err
		}
		if fields.Translations != nil {
			for _, translation := range fields.Translations {
				updTr := map[string]any{
					"name":        translation.Name,
					"content":     translation.Content,
					"explanation": translation.Explanation,
				}
				if err := tx.Model(&gormModels.FolkloreTranslation{}).
					Where("folklore_id = ? AND language = ?", id, translation.Language).Updates(updTr).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, utils.ErrHandler(err)
	}
	var folklore gormModels.Folklore
	if err := f.db.WithContext(ctx).Preload("Translations").First(&folklore, id).Error; err != nil {
		return nil, utils.ErrHandler(err)
	}
	domainFolklore := gormMappers.GormFolkloreToDomainModel(folklore)
	return &domainFolklore, nil
}

func (f FolkloreRepository) Delete(ctx context.Context, id int) error {
	if err := f.db.WithContext(ctx).Delete(&gormModels.Folklore{}, id).Error; err != nil {
		return utils.ErrHandler(err)
	}
	return nil
}

func (f FolkloreRepository) ToggleLike(ctx context.Context, folkloreID, userID int) (*models.Folklore, bool, error) {
	var like gormModels.FolkloreLike
	err := f.db.WithContext(ctx).Where("folklore_id = ? AND user_id = ?", folkloreID, userID).First(&like).Error
	liked := false
	newLike := gormModels.FolkloreLike{
		UserID:     uint(userID),
		FolkloreID: uint(folkloreID),
	}
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):

		err = f.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := tx.Create(&newLike).Error; err != nil {
				return err
			}
			if err := tx.Model(&gormModels.Folklore{}).Where("id = ?", folkloreID).Update("likes_count", gorm.Expr("likes_count + ?", 1)).Error; err != nil {
				return err
			}
			return nil
		})
		liked = true
	case err != nil:
		return nil, false, utils.ErrHandler(err)

	default:
		err = f.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := tx.Unscoped().Delete(&like).Error; err != nil {
				return err
			}
			if err := tx.Model(&gormModels.Folklore{}).Where("id = ?", folkloreID).UpdateColumn("likes_count", gorm.Expr("GREATEST(likes_count - 1, 0)")).Error; err != nil {
				return err
			}
			liked = false
			return nil
		})
		if err != nil {
			return nil, false, utils.ErrHandler(err)
		}
	}
	var folklore gormModels.Folklore
	if err := f.db.WithContext(ctx).Preload("Translations").Where("id = ?", folkloreID).First(&folklore).Error; err != nil {
		return nil, liked, utils.ErrHandler(err)
	}
	domainFolklore := gormMappers.GormFolkloreToDomainModel(folklore)
	return &domainFolklore, liked, nil
}

func (f FolkloreRepository) GetByQuery(ctx context.Context, query models.FolkloreFilter) ([]models.Folklore, error) {
	db := f.db.WithContext(ctx).Model(&gormModels.Folklore{})
	if query.Author != "" {
		db = db.Where("author = ?", query.Author)
	}
	if query.Region != "" {
		db = db.Where("region = ?", query.Region)
	}
	if query.Type != "" {
		db = db.Where("type = ?", query.Type)
	}
	if query.Search != "" {
		search := "%" + query.Search + "%"
		db = db.Where("content ILIKE ? OR name ILIKE ? OR author ILIKE ?", search, search, search)
	}
	if query.MinLikes > 0 {
		db = db.Where("likes_count > ?", query.MinLikes)
	}
	var folklores []gormModels.Folklore
	if err := db.WithContext(ctx).Find(&folklores).Error; err != nil {
		return nil, utils.ErrHandler(err)
	}
	var domainFolklore []models.Folklore
	for _, folklore := range folklores {
		domFolk := gormMappers.GormFolkloreToDomainModel(folklore)
		domainFolklore = append(domainFolklore, domFolk)
	}
	return domainFolklore, nil
}
