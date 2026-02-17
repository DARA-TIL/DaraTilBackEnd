package utils

import "DaraTilBackendV2/internal/domain/models"

func UpdateLessonFields(u models.UpdateLessonFields) map[string]any {
	updFields := make(map[string]any)
	if u.Name != nil {
		updFields["name"] = *u.Name
	}
	if u.Description != nil {
		updFields["description"] = *u.Description
	}
	if u.ImageUrl != nil {
		updFields["imageUrl"] = *u.ImageUrl
	}
	if u.Author != nil {
		updFields["author"] = *u.Author
	}
	if u.Reward != nil {
		updFields["reward"] = *u.Reward
	}
	if u.RequiredLevel != nil {
		updFields["required_level"] = *u.RequiredLevel
	}
	return updFields
}
func UpdateLessonBlockFields(u models.UpdateLessonBLockFields) map[string]any {
	updFields := make(map[string]any)
	if u.Name != nil {
		updFields["name"] = *u.Name
	}
	if u.ContentText != nil {
		updFields["content_text"] = *u.ContentText
	}
	if u.ContentType != nil {
		updFields["content_type"] = *u.ContentType
	}
	if u.ContentUrl != nil {
		updFields["content_url"] = *u.ContentUrl
	}
	return updFields
}
