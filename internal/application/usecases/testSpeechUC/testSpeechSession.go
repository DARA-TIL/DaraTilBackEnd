package testSpeechUC

import (
	"DaraTilBackendV2/internal/application/usecases/subscriptionUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"errors"
	"io"
)

type TestSpeechSessionUC struct {
	testRepo          repo.SpeechTestRepo
	sessionRepo       repo.SpeechTestSession
	userRepo          repo.UserRepo
	speechRecognizer  repo.SpeechRecognizer
	checkDailyUsageUC *subscriptionUC.CheckDailyActionLimitUC
}

func NewTestSpeechSessionUC(
	testRepo repo.SpeechTestRepo,
	sessionRepo repo.SpeechTestSession,
	userRepo repo.UserRepo,
	speechRecognizer repo.SpeechRecognizer,
	checkDailyUsageUC *subscriptionUC.CheckDailyActionLimitUC,
) *TestSpeechSessionUC {
	return &TestSpeechSessionUC{
		testRepo:          testRepo,
		sessionRepo:       sessionRepo,
		userRepo:          userRepo,
		speechRecognizer:  speechRecognizer,
		checkDailyUsageUC: checkDailyUsageUC,
	}
}

func (uc *TestSpeechSessionUC) StartSession(ctx context.Context, userID uint) (*models.SpeechTestSession, error) {
	session, err := uc.sessionRepo.GetActiveByUserID(ctx, userID)
	if err == nil {
		return session, nil
	}

	if !errors.Is(err, errs.ErrNotFound) {
		return nil, err
	}

	session, err = uc.sessionRepo.Create(ctx, models.SpeechTestSession{
		UserID:       userID,
		CorrectCount: 0,
		IsEnded:      false,
	})
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (uc *TestSpeechSessionUC) GetNextTest(ctx context.Context, userID uint) (*models.SpeechTest, error) {
	if err := uc.checkDailyUsageUC.Execute(ctx, userID, "speechTest"); err != nil {
		return nil, err
	}
	_, err := uc.sessionRepo.GetActiveByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, errs.ErrNotFound) {
			_, createErr := uc.sessionRepo.Create(ctx, models.SpeechTestSession{
				UserID:       userID,
				CorrectCount: 0,
				IsEnded:      false,
			})
			if createErr != nil {
				return nil, createErr
			}
		} else {
			return nil, err
		}
	}

	test, err := uc.sessionRepo.AddRandomNewTestToActiveSession(ctx, userID)
	if err != nil {
		return nil, err
	}

	return test, nil
}

func (uc *TestSpeechSessionUC) CheckPronounce(ctx context.Context, userID uint, testID uint, audio io.Reader) (*models.SpeechTestResult, error) {
	test, err := uc.testRepo.GetByID(ctx, testID)
	if err != nil {
		return nil, err
	}

	res, err := uc.speechRecognizer.IsCorrectPronounce(ctx, test.KzText, audio)
	if err != nil {
		return nil, err
	}

	if res.IsCorrectPronounce {
		if err := uc.sessionRepo.IncreaseCorrectCount(ctx, userID); err != nil {
			return nil, err
		}
	}

	return &models.SpeechTestResult{
		SpeechTest: *test,
		AiResponse: res.Explanation,
		IsCorrect:  res.IsCorrectPronounce,
	}, nil
}

func (uc *TestSpeechSessionUC) EndSession(ctx context.Context, userID uint) (*models.SpeechTestSessionResult, error) {
	session, err := uc.sessionRepo.GetActiveByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	reward := session.CorrectCount * 5

	if reward > 0 {
		lvlUpRes := uc.userRepo.LvlUp(ctx, userID, reward)
		if lvlUpRes.Err != nil {
			return nil, lvlUpRes.Err
		}
	}

	if err := uc.sessionRepo.EndActiveSession(ctx, userID); err != nil {
		return nil, err
	}

	session.IsEnded = true

	return &models.SpeechTestSessionResult{
		SpeechTestSession: *session,
		Reward:            reward,
	}, nil
}
