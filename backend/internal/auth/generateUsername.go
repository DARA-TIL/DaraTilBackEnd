package auth

import (
	"DaraTilBackEnd/backend/internal/database"
	"DaraTilBackEnd/backend/internal/models"
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

// Генерим уникальный ник: base, base_1, base_2, ...
func generateUniqueUsername(base string) string {
	base = normalizeUsername(base)

	// сначала пробуем без суффикса
	username := base
	var count int64
	database.DB.Model(&models.User{}).
		Where("username = ?", username).
		Count(&count)

	if count == 0 {
		return username
	}

	// если занят - перебираем суффиксы
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

	// на всякий пожарный fallback
	return fmt.Sprintf("%s_%d", base, count+1)
}
