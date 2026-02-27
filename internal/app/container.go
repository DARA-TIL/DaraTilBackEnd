package app

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/application/usecases/folkloreUC"
	"DaraTilBackendV2/internal/application/usecases/jwtTokenUC"
	"DaraTilBackendV2/internal/application/usecases/lessonUC"
	"DaraTilBackendV2/internal/application/usecases/testUC"
	"DaraTilBackendV2/internal/application/usecases/userUC"
	"DaraTilBackendV2/internal/config"
	"DaraTilBackendV2/internal/infrastructure/ai/gemini"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/postgres"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/repository"
	"DaraTilBackendV2/internal/presentation/http/service/folklore"
	"DaraTilBackendV2/internal/presentation/http/service/jwt"
	"DaraTilBackendV2/internal/presentation/http/service/lesson"
	"DaraTilBackendV2/internal/presentation/http/service/test"
	"DaraTilBackendV2/internal/presentation/http/service/user"
	"DaraTilBackendV2/internal/presentation/http/service/userActivity"
)

type Container struct {
	UserHandler         *user.UserHandler
	JwtHandler          *jwt.JwtTokenHandler
	FolkloreHandler     *folklore.FolkloreHandler
	LessonHandler       *lesson.LessonHandler
	TestHandler         *test.TestHandler
	userActivityHandler *userActivity.UserActivityHandler
}

func NewContainer(cfg *config.Config) *Container {

	// DB
	pg := postgres.NewPostgresRepository(cfg)
	db := pg.Db

	// Repos
	userRepo := repository.NewUserRepository(db)
	jwtRepo := repository.NewJwtRepository(db)
	folkloreRepo := repository.NewFolkloreRepository(db)
	lessonRepo := repository.NewLessonRepository(db)
	testRepo := repository.NewTestRepository(db)
	userActivityRepo := repository.NewUserActivityRepository(db)
	streakRepo := repository.NewStreakRepository(db)

	//AI
	geminiAI := gemini.NewGeminiAI(cfg)

	//UserActivityService
	StreakService := services.NewStreakService(streakRepo)
	userActivityService := services.NewUserActivityService(userActivityRepo, StreakService)

	// User UCs
	createUserUC := userUC.NewCreateUC(userRepo)
	getAllUsersUC := userUC.NewGetAllUC(userRepo)
	getByEmailUC := userUC.NewGetByEmailUC(userRepo)
	getUserByIDUC := userUC.NewGetByIdUC(userRepo)
	lvlUpUC := userUC.NewLvlUpUC(userRepo)
	updateUC := userUC.NewUpdateUC(userRepo)
	getByUsernameUC := userUC.NewGetByUsernameUC(userRepo)

	// JWT UCs
	createTokenUC := jwtTokenUC.NewCreateUC(jwtRepo)
	issueTokenUC := jwtTokenUC.NewIssueTokenUC(*createTokenUC, cfg)
	findTokenUC := jwtTokenUC.NewFindUC(jwtRepo)
	revokeJwtUC := jwtTokenUC.NewRevokeJwtUC(jwtRepo)

	//folklore Ucs
	createFolkloreUC := folkloreUC.NewCreateUC(folkloreRepo, geminiAI)
	deleteFolkloreUC := folkloreUC.NewDeleteUC(folkloreRepo)
	getAllFolkloreUC := folkloreUC.NewGetAllUC(folkloreRepo)
	getByIdFolkloreUC := folkloreUC.NewGetByFolkloreIDUC(folkloreRepo, userActivityService)
	getByQueryFolkloreUC := folkloreUC.NewGetByQueryUC(folkloreRepo)
	getLikedFolkloreUC := folkloreUC.NewGetLikedFolkloreUC(folkloreRepo)
	toggleLikeFolkloreUC := folkloreUC.NewToggleLikeUC(folkloreRepo, userActivityService)
	updateFolkloreUC := folkloreUC.NewUpdateUC(folkloreRepo, geminiAI)

	//LessonUCS
	createLessonUC := lessonUC.NewCreateUC(lessonRepo)
	createBlockLessonUC := lessonUC.NewCreateBlockUC(lessonRepo)

	deleteLessonUC := lessonUC.NewDeleteUC(lessonRepo)
	deleteBlockLessonUC := lessonUC.NewDeleteBlockUC(lessonRepo)

	getAllLessonUC := lessonUC.NewGetAllUC(lessonRepo)
	getByIDLessonUC := lessonUC.NewGetByIDUC(lessonRepo)

	updateLessonUC := lessonUC.NewUpdateUC(lessonRepo)
	updateBlockLessonUC := lessonUC.NewUpdateBlockUC(lessonRepo)

	finishLessonUC := lessonUC.NewFinishLessonUC(lessonRepo, userActivityService)
	getFinishedLessonsUC := lessonUC.NewGetFinishedLessonsUC(lessonRepo)
	getLessonResultsUC := lessonUC.NewGetLessonResultsUC(lessonRepo)
	getBestResultForLessonUC := lessonUC.NewGetBestResultForLessonUC(lessonRepo)

	//TestUCS
	createTestUC := testUC.NewCreateUC(testRepo)
	createQuestionUC := testUC.NewCreateQuestionUC(testRepo)
	createOptionUC := testUC.NewCreateOptionUC(testRepo)

	deleteTestUC := testUC.NewDeleteUC(testRepo)
	deleteQuestionUC := testUC.NewDeleteQuestionUC(testRepo)
	deleteOptionUC := testUC.NewDeleteOptionUC(testRepo)

	getByIDTestUC := testUC.NewGetByIDUC(testRepo)
	getByLessonIDTestUC := testUC.NewGetByLessonIDUC(testRepo)

	updateTestUC := testUC.NewUpdateUC(testRepo)
	updateQuestionUC := testUC.NewUpdateQuestionUC(testRepo)
	updateQuestionOptionUC := testUC.NewUpdateQuestionOptionUC(testRepo)

	checkAnswerUC := testUC.NewCheckAnswersUC(testRepo)

	// Handlers
	jwtHandler := jwt.NewJwtTokenHandler(
		createTokenUC,
		findTokenUC,
		revokeJwtUC,
		getUserByIDUC,
		StreakService,
		cfg,
	)

	userHandler := user.NewUserHandler(
		createUserUC,
		getAllUsersUC,
		getByEmailUC,
		getUserByIDUC,
		lvlUpUC,
		updateUC,
		issueTokenUC,
		getByUsernameUC,
		getLikedFolkloreUC,
		StreakService,
		cfg,
	)

	folkloreHandler := folklore.NewFolkloreHandler(
		createFolkloreUC,
		updateFolkloreUC,
		getByIdFolkloreUC,
		deleteFolkloreUC,
		getByQueryFolkloreUC,
		getAllFolkloreUC,
		toggleLikeFolkloreUC,
		getLikedFolkloreUC,
	)
	lessonHandler := lesson.NewLessonHandler(
		createLessonUC,
		createBlockLessonUC,
		deleteLessonUC,
		deleteBlockLessonUC,
		getAllLessonUC,
		getByIDLessonUC,
		updateLessonUC,
		updateBlockLessonUC,
		checkAnswerUC,
		finishLessonUC,
		getFinishedLessonsUC,
		getLessonResultsUC,
		getUserByIDUC,
		lvlUpUC,
		getBestResultForLessonUC,
	)
	testHandler := test.NewTestHandler(
		createTestUC,
		createQuestionUC,
		createOptionUC,
		deleteOptionUC,
		deleteQuestionUC,
		deleteTestUC,
		getByIDTestUC,
		getByLessonIDTestUC,
		updateQuestionOptionUC,
		updateQuestionUC,
		updateTestUC,
	)
	userActivityHandler := userActivity.NewUserActivityHandler(userActivityService)
	return &Container{
		UserHandler:         userHandler,
		JwtHandler:          jwtHandler,
		FolkloreHandler:     folkloreHandler,
		LessonHandler:       lessonHandler,
		TestHandler:         testHandler,
		userActivityHandler: userActivityHandler,
	}
}
