package dto

type ActionRule struct {
	Action string          `json:"action" binding:"required"`
	Rules  map[string]bool `json:"rules" binding:"required"`
}
