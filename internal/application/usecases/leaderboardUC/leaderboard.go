package leaderboardUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type LeaderboardUC struct {
	repo repo.LeaderboardRepo
}

func NewLeaderboardUC(repo repo.LeaderboardRepo) *LeaderboardUC {
	return &LeaderboardUC{repo: repo}
}

func (l *LeaderboardUC) GetByStreak(ctx context.Context, streak int) ([]models.User, error) {
	return l.repo.GetByStreak(ctx, streak)
}
func (l *LeaderboardUC) GetByWords(ctx context.Context, limit int) ([]models.UserProfile, error) {
	return l.repo.GetByWords(ctx, limit)
}
func (l *LeaderboardUC) GetByXP(ctx context.Context, limit int) ([]models.User, error) {
	return l.repo.GetByXP(ctx, limit)
}
