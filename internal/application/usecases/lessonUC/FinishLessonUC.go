package lessonUC

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/application/utils"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type FinishLessonUC struct {
	repo                repo.LessonRepo
	userActivityService *services.UserActivityService
	Publisher           services.Publisher
}

func NewFinishLessonUC(repo repo.LessonRepo, uas *services.UserActivityService, pub services.Publisher) *FinishLessonUC {
	return &FinishLessonUC{repo: repo, userActivityService: uas, Publisher: pub}
}

func (uc *FinishLessonUC) Execute(ctx context.Context, lesRes models.LessonResult) (*models.LessonResult, services.StreakUpdateResult, error) {
	lessonResult, err := uc.repo.FinishLesson(ctx, lesRes)
	streak := services.NoChange
	if err != nil {
		return nil, 0, err
	}
	if lessonResult.Pass {
		uc.Publisher.NotifySubscribers(ctx, services.Event{
			Action: models.Lesson_completed,
			UserID: lesRes.UserID,
		})
		streak, err = uc.userActivityService.LogActivityWithStreak(ctx, models.Lesson_completed, "lesson", lessonResult.UserID, lessonResult.LessonID)
		if err != nil {
			utils.ErrLoggerUserActivity(err)
		}
	}
	return lessonResult, streak, nil
}
