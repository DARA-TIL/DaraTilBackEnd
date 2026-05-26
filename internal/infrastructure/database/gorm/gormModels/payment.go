package gormModels

import (
	"DaraTilBackendV2/internal/domain/models"
	"time"
)

type Payment struct {
	ID uint `gorm:"primaryKey"`

	UserID uint `gorm:"not null;index"`
	PlanID uint `gorm:"not null;index"`

	Plan SubscriptionPlan `gorm:"foreignKey:PlanID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`

	Amount   int    `gorm:"not null"`
	Currency string `gorm:"type:varchar(10);not null;default:'KZT'"`

	Status   models.PaymentStatus   `gorm:"type:varchar(20);not null;default:'pending';index"`
	Provider models.PaymentProvider `gorm:"type:varchar(50);not null;index"`

	ProviderPaymentID *string `gorm:"type:varchar(255);index"`
	PaymentURL        *string `gorm:"type:text"`

	PaidAt *time.Time `gorm:"index"`

	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}
