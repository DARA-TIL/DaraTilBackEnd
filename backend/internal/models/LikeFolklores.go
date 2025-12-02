package models

import (
	"gorm.io/gorm"
)

type FolkloreLike struct {
	gorm.Model

	UserID     uint `gorm:"not null;uniqueIndex:user_folklore_idx" json:"userId"`
	FolkloreID uint `gorm:"not null;uniqueIndex:user_folklore_idx" json:"folkloreId"`

	// связи
	User     User     `gorm:"foreignKey:UserID"`
	Folklore Folklore `gorm:"foreignKey:FolkloreID"`
}
