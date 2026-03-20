package models

type ActionRule struct {
	Action Actions
	Rules  map[ActionTrigger]bool
}
