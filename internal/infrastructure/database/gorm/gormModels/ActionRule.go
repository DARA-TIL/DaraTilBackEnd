package gormModels

import "gorm.io/datatypes"

type ActionRule struct {
	ID     uint           `gorm:"primaryKey"`
	Action string         `gorm:"uniqueIndex"`
	Rules  datatypes.JSON `gorm:"type:jsonb"`
}
