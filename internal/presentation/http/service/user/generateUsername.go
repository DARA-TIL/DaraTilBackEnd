package user

import (
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"
	"fmt"
	"strings"
)

func normalizeUsername(base string) string {
	base = strings.TrimSpace(base)
	base = strings.ToLower(base)
	base = strings.ReplaceAll(base, " ", "_")
	if base == "" {
		base = "user"
	}
	return base
}

func GenerateUniqueUsername(ctx context.Context, base string, h *UserHandler) (string, error) {
	logger.Info("Generate Unique Username")
	base = normalizeUsername(base)

	username := base
	users, err := h.GetByUsernameUC.Execute(ctx, base)
	if err != nil {
		logger.Error("Get User By Username Failed")
		return "", err
	}

	if len(users) == 0 {
		return username, nil
	}

	for i := 1; i <= 50; i++ {
		candidate := fmt.Sprintf("%s_%d", base, i)
		users, err = h.GetByUsernameUC.Execute(ctx, candidate)
		if err != nil {
			logger.Error("Get User By Username Failed")
			return "", err
		}
		if len(users) == 0 {
			logger.Info(fmt.Sprintf("Created Nickname: %s", candidate))
			return candidate, nil
		}
	}
	logger.Info(fmt.Sprintf("Created Nickname: %s_%d", base, len(users)+1))

	return fmt.Sprintf("%s_%d", base, len(users)+1), nil
}
