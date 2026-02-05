package dtoMappers

import (
	"DaraTilBackendV2/internal/application/models"
	"DaraTilBackendV2/internal/presentation/dto"
)

func DtoTokenPairToDomain(dto dto.TokenPair) models.TokenPair {
	return models.TokenPair{
		AccessToken:  dto.AccessToken,
		RefreshToken: dto.RefreshToken,
	}
}
func TokenPairToDto(tokenPair models.TokenPair) dto.TokenPair {
	return dto.TokenPair{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	}
}

func DtoUserClaimsToDomain(dto dto.UserClaims) models.UserClaims {
	return models.UserClaims{
		UserID:   dto.UserID,
		Username: dto.Username,
		Email:    dto.Email,
		Role:     dto.Role,
	}
}
func UserClaimsToDto(claims models.UserClaims) dto.UserClaims {
	return dto.UserClaims{
		UserID:   claims.UserID,
		Username: claims.Username,
		Email:    claims.Email,
		Role:     claims.Role,
	}
}
func DtoCustomClaimsToDomain(dto dto.CustomClaims) models.CustomClaims {
	return models.CustomClaims{
		UserID:           dto.UserID,
		Username:         dto.Username,
		Email:            dto.Email,
		Role:             dto.Role,
		RegisteredClaims: dto.RegisteredClaims,
	}
}
func CustomClaimsToDto(claims models.CustomClaims) dto.CustomClaims {
	return dto.CustomClaims{
		UserID:           claims.UserID,
		Username:         claims.Username,
		Email:            claims.Email,
		Role:             claims.Role,
		RegisteredClaims: claims.RegisteredClaims,
	}
}
func IssueTokenResultToDto(res models.IssueTokenResult) dto.TokenPair {
	return dto.TokenPair{
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
	}
}
