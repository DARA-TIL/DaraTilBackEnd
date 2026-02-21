package testUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CheckAnswersUC struct {
	repo repo.TestRepo
}

func NewCheckAnswersUC(repo repo.TestRepo) *CheckAnswersUC {
	return &CheckAnswersUC{repo: repo}
}

func (uc *CheckAnswersUC) Execute(ctx context.Context, ans models.Answers) (*models.LessonResult, error) {
	test, err := uc.repo.GetCorrectAnswers(ctx, ans.TestID)
	overallQ := len(test)
	if err != nil {
		return nil, err
	}
	correctSum := 0
	userAnswers := ans.UserAns
	for key, value := range test {
		if userAnswers[key] == value {
			correctSum += 1
		}
	}
	resPercent := float64(correctSum) / float64(overallQ) * 100
	pass := false
	if resPercent >= 70 {
		pass = true
	}
	testRes := models.LessonResult{
		UserID:   ans.UserID,
		TestID:   ans.TestID,
		LessonID: ans.LessonID,
		Result:   uint(resPercent),
		Pass:     pass,
	}
	return &testRes, nil
}
