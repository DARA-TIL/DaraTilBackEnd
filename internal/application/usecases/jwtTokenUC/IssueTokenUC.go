package jwtTokenUC

import (
	"DaraTilBackendV2/internal/application/models"
	"DaraTilBackendV2/internal/application/utils"
	"DaraTilBackendV2/internal/config"
	errs "DaraTilBackendV2/internal/domain/domErr"
	models2 "DaraTilBackendV2/internal/domain/models"
	"context"
	"time"
)

type IssueTokenUC struct {
	CreateUc CreateTokenUC
	cfg      *config.Config
}

func NewIssueTokenUC(createUC CreateTokenUC, cfg *config.Config) *IssueTokenUC {
	return &IssueTokenUC{
		CreateUc: createUC,
		cfg:      cfg,
	}
}

func (uc *IssueTokenUC) Execute(ctx context.Context, meta models.TokenMeta, userClaims models.UserClaims) (*models.IssueTokenResult, error) {
	tokens, err := utils.GenerateTokenPair(userClaims, uc.cfg)
	if err != nil {
		return nil, errs.ErrInternal
	}
	now := time.Now()
	refreshExp := now.Add(time.Hour * time.Duration(uc.cfg.Jwt.JwtRefreshExpiresHours))

	token := models2.Token{
		UserID:           userClaims.UserID,
		RefreshTokenHash: utils.HashToken(tokens.RefreshToken),
		Device:           meta.Device,
		IpAddress:        meta.IpAddress,
		UserAgent:        meta.UserAgent,
		Expires:          refreshExp,
		LastUsed:         now,
	}
	_, err = uc.CreateUc.Execute(ctx, token)
	if err != nil {
		return nil, err
	}
	return &models.IssueTokenResult{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		RefreshExp:   refreshExp,
	}, nil
}
