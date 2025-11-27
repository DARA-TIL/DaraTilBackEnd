package auth

import (
	"DaraTilBackEnd/backend/internal/database"
	"DaraTilBackEnd/backend/internal/models"
	"fmt"
	"strings"
)

// for cases if username is created, but login with google
func normalizeUsername(base string) string {
	base = strings.TrimSpace(base)
	base = strings.ToLower(base)
	base = strings.ReplaceAll(base, " ", "_")
	if base == "" {
		base = "user"
	}
	return base
}

func generateUniqueUsername(base string) string {
	base = normalizeUsername(base)

	username := base
	var count int64
	database.DB.Model(&models.User{}).
		Where("username = ?", username).
		Count(&count)

	if count == 0 {
		return username
	}

	for i := 1; i <= 50; i++ {
		candidate := fmt.Sprintf("%s_%d", base, i)
		count = 0
		database.DB.Model(&models.User{}).
			Where("username = ?", candidate).
			Count(&count)

		if count == 0 {
			return candidate
		}
	}

	return fmt.Sprintf("%s_%d", base, count+1)
}
