package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"

	"gorm.io/gorm"
)

type TestRepository struct {
	db *gorm.DB
}

func NewTestRepository(db *gorm.DB) *TestRepository {
	return &TestRepository{db: db}
}

func (t TestRepository) Create(ctx context.Context, test models.Test) (*models.Test, error) {
	gormTest := gormMappers.TestToGorm(test)
	if err := t.db.WithContext(ctx).Create(&gormTest).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	test = gormMappers.GormTestToDomain(gormTest)
	return &test, nil
}

func (t TestRepository) CreateQuestion(ctx context.Context, question models.Question) (*models.Question, error) {
	gormQuestion := gormMappers.QuestionToGorm(question)
	if err := t.db.WithContext(ctx).Create(&gormQuestion).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	question = gormMappers.GormQuestionToDomain(gormQuestion)
	return &question, nil
}

func (t TestRepository) CreateOption(ctx context.Context, option models.QuestionOption) (*models.QuestionOption, error) {
	gormOption := gormMappers.QuestionOptionToGorm(option)
	if err := t.db.WithContext(ctx).Create(&gormOption).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	option = gormMappers.GormQuestionOptionToDomain(gormOption)
	return &option, nil
}

func (t TestRepository) GetById(ctx context.Context, id uint) (*models.Test, error) {
	var test gormModels.Test
	err := t.db.WithContext(ctx).Preload("Questions.Options").First(&test, id).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	testDom := gormMappers.GormTestToDomain(test)
	return &testDom, nil
}

func (t TestRepository) GetByLessonId(ctx context.Context, id uint) (*models.Test, error) {
	var test gormModels.Test
	err := t.db.WithContext(ctx).Preload("Questions.Options").Where("lesson_id = ?", id).First(&test).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	testDom := gormMappers.GormTestToDomain(test)
	return &testDom, nil
}
func (t TestRepository) GetOptionByID(ctx context.Context, id uint) (*models.QuestionOption, error) {
	var qo gormModels.QuestionOption
	if err := t.db.WithContext(ctx).First(&qo, id).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	qoDom := gormMappers.GormQuestionOptionToDomain(qo)
	return &qoDom, nil
}
func (t TestRepository) Delete(ctx context.Context, id uint) error {
	if err := t.db.WithContext(ctx).Unscoped().Where("id = ?", id).Delete(&gormModels.Test{}).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (t TestRepository) DeleteQuestion(ctx context.Context, id uint) error {
	if err := t.db.WithContext(ctx).Unscoped().Where("id = ?", id).Delete(&gormModels.Question{}).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}
func (t TestRepository) DeleteOption(ctx context.Context, id uint) error {
	if err := t.db.WithContext(ctx).Unscoped().Where("id = ?", id).Delete(&gormModels.QuestionOption{}).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}
func (t TestRepository) Update(ctx context.Context, upd models.TestUpdate) (*models.Test, error) {
	updates := make(map[string]any)
	err := t.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if upd.QuestionsUpd != nil {
			for _, question := range upd.QuestionsUpd {
				_, err := UpdateQuestionTransaction(tx, question)
				if err != nil {
					return err
				}
				if question.QuestionOptionsUpd != nil {
					for _, option := range question.QuestionOptionsUpd {
						_, err := UpdateOptionTransaction(tx, option)
						if err != nil {
							return err
						}
					}
				}
			}
		}
		if upd.Reward != nil {
			updates["reward"] = *upd.Reward
			err := tx.Model(&gormModels.Test{}).Where("id = ?", *upd.ID).Updates(updates).Error
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	testGorm, err := t.GetById(ctx, *upd.ID)
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	return testGorm, nil
}
func (t TestRepository) UpdateQuestion(ctx context.Context, upd models.QuestionUpdate) (*models.Question, error) {
	updates := make(map[string]any)
	err := t.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if upd.QuestionOptionsUpd != nil {
			for _, option := range upd.QuestionOptionsUpd {
				_, err := UpdateOptionTransaction(tx, option)
				if err != nil {
					return err
				}
			}
		}
		if upd.Text != nil {
			updates["text"] = *upd.Text
		}
		if err := tx.Model(&gormModels.Question{}).Where("id = ?", *upd.ID).Updates(updates).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	var qGorm gormModels.Question
	err = t.db.Model(&gormModels.Question{}).Where("id = ?", *upd.ID).First(&qGorm).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	q := gormMappers.GormQuestionToDomain(qGorm)
	return &q, nil
}

func UpdateQuestionTransaction(tx *gorm.DB, upd models.QuestionUpdate) (*models.Question, error) {
	updates := map[string]any{}
	if upd.Text != nil {
		updates["text"] = *upd.Text
	}
	if err := tx.Model(gormModels.Question{}).Where("id = ?", *upd.ID).Updates(updates).Error; err != nil {
		return nil, err
	}
	var q gormModels.Question
	err := tx.Preload("Options").First(&q, *upd.ID).Error
	if err != nil {
		return nil, err
	}
	qDom := gormMappers.GormQuestionToDomain(q)
	return &qDom, nil
}

func (t TestRepository) UpdateQuestionOption(ctx context.Context, upd models.QuestionOptionsUpdate) (*models.QuestionOption, error) {
	updates := make(map[string]any)
	if upd.Text != nil {
		updates["text"] = *upd.Text
	}
	if upd.IsCorrect != nil {
		updates["is_correct"] = *upd.IsCorrect
	}
	if err := t.db.WithContext(ctx).Model(&gormModels.QuestionOption{}).Where("id = ?", *upd.ID).Updates(updates).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	var qo gormModels.QuestionOption
	err := t.db.WithContext(ctx).First(&qo, *upd.ID).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	qoDom := gormMappers.GormQuestionOptionToDomain(qo)
	return &qoDom, nil
}

func UpdateOptionTransaction(tx *gorm.DB, upd models.QuestionOptionsUpdate) (*models.QuestionOption, error) {
	updates := make(map[string]any)
	if upd.Text != nil {
		updates["text"] = *upd.Text
	}
	if upd.IsCorrect != nil {
		updates["is_correct"] = *upd.IsCorrect
	}
	if err := tx.Model(gormModels.QuestionOption{}).Where("id = ?", *upd.ID).Updates(updates).Error; err != nil {
		return nil, err
	}
	var o gormModels.QuestionOption
	err := tx.First(&o, *upd.ID).Error
	if err != nil {
		return nil, err
	}
	oDom := gormMappers.GormQuestionOptionToDomain(o)
	return &oDom, nil
}
