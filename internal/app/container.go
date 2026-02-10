package app

import (
	"DaraTilBackendV2/internal/application/usecases/jwtTokenUC"
	"DaraTilBackendV2/internal/application/usecases/userUC"
	"DaraTilBackendV2/internal/config"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/postgres"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/repository"
	"DaraTilBackendV2/internal/presentation/http/service/jwt"
	"DaraTilBackendV2/internal/presentation/http/service/user"
)

type Container struct {
	UserHandler *user.UserHandler
	JwtHandler  *jwt.JwtTokenHandler
}

func NewContainer(cfg *config.Config) *Container {

	// DB
	pg := postgres.NewPostgresRepository(cfg)
	db := pg.Db

	// Repos
	userRepo := repository.NewUserRepository(db)
	jwtRepo := repository.NewJwtRepository(db)

	// User UCs
	createUserUC := userUC.NewCreateUserUC(userRepo)
	getAllUsersUC := userUC.NewGetAllUsersUC(userRepo)
	getByEmailUC := userUC.NewGetUserByEmailUC(userRepo)
	getByIdUC := userUC.NewGetUserByIdUC(userRepo)
	lvlUpUC := userUC.NewLvlUpUC(userRepo)
	updateUC := userUC.NewUpdateUserUC(userRepo)
	getByUsernameUC := userUC.NewGetByUsernameUC(userRepo)

	// JWT UCs
	createTokenUC := jwtTokenUC.NewCreateTokenUC(jwtRepo)
	issueTokenUC := jwtTokenUC.NewIssueTokenUC(*createTokenUC, cfg)
	findTokenUC := jwtTokenUC.NewFindTokenUC(jwtRepo)
	revokeJwtUC := jwtTokenUC.NewRevokeJwtUC(jwtRepo)

	// Handlers
	jwtHandler := jwt.NewJwtTokenHandler(
		createTokenUC,
		findTokenUC,
		revokeJwtUC,
		getByIdUC,
		cfg,
	)

	userHandler := user.NewUserHandler(
		createUserUC,
		getAllUsersUC,
		getByEmailUC,
		getByIdUC,
		lvlUpUC,
		updateUC,
		issueTokenUC,
		getByUsernameUC,
		cfg,
	)

	return &Container{
		UserHandler: userHandler,
		JwtHandler:  jwtHandler,
	}
}
