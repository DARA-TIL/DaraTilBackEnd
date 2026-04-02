package app

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/application/usecases/achievementUC"
	"DaraTilBackendV2/internal/application/usecases/achievementUC/userAchievementUC"
	"DaraTilBackendV2/internal/application/usecases/actionRuleUC"
	"DaraTilBackendV2/internal/application/usecases/folkloreUC"
	"DaraTilBackendV2/internal/application/usecases/jwtTokenUC"
	"DaraTilBackendV2/internal/application/usecases/lessonUC"
	"DaraTilBackendV2/internal/application/usecases/regionSlangUC"
	"DaraTilBackendV2/internal/application/usecases/regionSlangUC/regionSlangTranslationsUC"
	"DaraTilBackendV2/internal/application/usecases/regionTraditionsUC"
	"DaraTilBackendV2/internal/application/usecases/regionTraditionsUC/regionTraditionTranslationsUC"
	"DaraTilBackendV2/internal/application/usecases/regionUC"
	"DaraTilBackendV2/internal/application/usecases/regionUC/regionTranslationsUC"
	"DaraTilBackendV2/internal/application/usecases/testUC"
	"DaraTilBackendV2/internal/application/usecases/userUC"
	"DaraTilBackendV2/internal/config"
	"DaraTilBackendV2/internal/infrastructure/ai/gemini"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/postgres"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/repository"
	"DaraTilBackendV2/internal/presentation/http/service/achievement"
	"DaraTilBackendV2/internal/presentation/http/service/actionRule"
	"DaraTilBackendV2/internal/presentation/http/service/folklore"
	"DaraTilBackendV2/internal/presentation/http/service/jwt"
	"DaraTilBackendV2/internal/presentation/http/service/lesson"
	"DaraTilBackendV2/internal/presentation/http/service/region"
	"DaraTilBackendV2/internal/presentation/http/service/test"
	"DaraTilBackendV2/internal/presentation/http/service/user"
	"DaraTilBackendV2/internal/presentation/http/service/userActivity"
	"DaraTilBackendV2/internal/presentation/http/service/ws"
)

type Container struct {
	UserHandler            *user.UserHandler
	JwtHandler             *jwt.JwtTokenHandler
	FolkloreHandler        *folklore.FolkloreHandler
	LessonHandler          *lesson.LessonHandler
	TestHandler            *test.TestHandler
	UserActivityHandler    *userActivity.UserActivityHandler
	RegionHandler          *region.RegionHandler
	RegionTraditionHandler *region.RegionTraditionHandler
	RegionSlangHandler     *region.RegionSlangHandler
	AchievementHandler     *achievement.AchievementHandler
	UserAchievementHandler *achievement.UserAchievementHandler
	ActionRuleHandler      *actionRule.ActionRuleHandler
	WebSocketHandler       *ws.WebSocketManager
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
	regionRepo := repository.NewRegionRepository(db)
	regionTranslationRepo := repository.NewRegionTranslationRepository(db)
	regionTraditionRepo := repository.NewRegionTraditionsRepository(db)
	regionTraditionTranslationRepo := repository.NewRegionTraditionTranslationRepository(db)
	regionSlangRepo := repository.NewRegionSlangRepository(db)
	regionSlangTranslationRepo := repository.NewRegionSlangTranslationRepository(db)
	achievementRepo := repository.NewAchievementRepository(db)
	userAchievementRepo := repository.NewUserAchievementRepository(db)
	actionRuleRepo := repository.NewActionRuleRepository(db)
	//AI
	geminiAI := gemini.NewGeminiAI(cfg)

	//UserActivityService
	streakService := services.NewStreakService(streakRepo)
	userActivityService := services.NewUserActivityService(userActivityRepo)

	publisher := services.NewActionPublisher(actionRuleRepo)

	// ActionRuleUCS
	createActionRuleUC := actionRuleUC.NewCreateUC(actionRuleRepo)
	createMultiActionRuleUC := actionRuleUC.NewCreateMultiUC(actionRuleRepo)
	updateActionRuleUC := actionRuleUC.NewUpdateUC(actionRuleRepo)
	deleteActionRuleUC := actionRuleUC.NewDeleteUC(actionRuleRepo)
	getAllActionRuleUC := actionRuleUC.NewGetAllUC(actionRuleRepo)
	getActionRuleByActionUC := actionRuleUC.NewGetByActionUC(actionRuleRepo)

	//AchievementsUCS
	createAchievementUC := achievementUC.NewCreateUC(achievementRepo)
	deleteAchievementUC := achievementUC.NewDeleteUC(achievementRepo)
	getAllAchievementUC := achievementUC.NewGetAllUC(achievementRepo)
	getAchievementByIDUC := achievementUC.NewGetByIDUC(achievementRepo)
	updateAchievementUC := achievementUC.NewUpdateUC(achievementRepo)

	//UserAchievementsUCs
	createUserAchievementUC := userAchievementUC.NewCreateUC(userAchievementRepo)
	deleteUserAchievementUC := userAchievementUC.NewDeleteUC(userAchievementRepo)
	getUserAchievementByIDUC := userAchievementUC.NewGetByIDUC(userAchievementRepo)
	updateUserAchievementUC := userAchievementUC.NewUpdateUC(userAchievementRepo)
	increaseUserAchievementSub := userAchievementUC.NewIncrementQuantityUC(userAchievementRepo, achievementRepo)
	getUaByUserIDUC := userAchievementUC.NewGetByUserIDUC(userAchievementRepo)

	publisher.AddSubscriber(increaseUserAchievementSub)
	publisher.AddSubscriber(userActivityService)
	publisher.AddSubscriber(streakService)

	// User UCs
	createUserUC := userUC.NewCreateUC(userRepo)
	getAllUsersUC := userUC.NewGetAllUC(userRepo)
	getByEmailUC := userUC.NewGetByEmailUC(userRepo)
	getUserByIDUC := userUC.NewGetByIdUC(userRepo)
	lvlUpUC := userUC.NewLvlUpUC(userRepo, publisher)
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
	getByIdFolkloreUC := folkloreUC.NewGetByFolkloreIDUC(folkloreRepo, publisher)
	getByQueryFolkloreUC := folkloreUC.NewGetByQueryUC(folkloreRepo)
	getLikedFolkloreUC := folkloreUC.NewGetLikedFolkloreUC(folkloreRepo)
	toggleLikeFolkloreUC := folkloreUC.NewToggleLikeUC(folkloreRepo, publisher)
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

	finishLessonUC := lessonUC.NewFinishLessonUC(lessonRepo, publisher)
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

	//RegionUCs
	createRegionUC := regionUC.NewCreateUC(regionRepo)
	deleteRegionUC := regionUC.NewDeleteUC(regionRepo)
	getAllRegionUC := regionUC.NewGetAllUC(regionRepo)
	getRegionByIDUC := regionUC.NewGetByIDUC(regionRepo)
	updateRegionUC := regionUC.NewUpdateUC(regionRepo)
	createMultiUC := regionUC.NewCreateMultiUC(regionRepo)
	getByCode := regionUC.NewGetByCodeUC(regionRepo)

	//RegionTranslationsUCs
	createRegionTranslationUC := regionTranslationsUC.NewCreateUC(regionTranslationRepo)
	deleteRegionTranslationUC := regionTranslationsUC.NewDeleteUC(regionTranslationRepo)
	getRegionTranslationByIDUC := regionTranslationsUC.NewGetByIDUC(regionTranslationRepo)
	getTranslationsByRegionIDUC := regionTranslationsUC.NewGetByRegionUC(regionTranslationRepo)
	updateRegionTranslationUC := regionTranslationsUC.NewUpdateUC(regionTranslationRepo)

	//RegionSlangUcs
	createRegionSlangUC := regionSlangUC.NewCreateUC(regionSlangRepo)
	deleteRegionSlangUC := regionSlangUC.NewDeleteUC(regionSlangRepo)
	getRegionSlangByIDUC := regionSlangUC.NewGetByIDUC(regionSlangRepo, userActivityService, publisher)
	getSlangByRegionIDUC := regionSlangUC.NewGetByRegionUC(regionSlangRepo)
	updateRegionSlangUC := regionSlangUC.NewUpdateUC(regionSlangRepo)

	//RegionSlangTranslationsUcs
	createRegionSlangTranslationUC := regionSlangTranslationsUC.NewCreateUC(regionSlangTranslationRepo)
	deleteRegionSlangTranslationUC := regionSlangTranslationsUC.NewDeleteUC(regionSlangTranslationRepo)
	getRegionSlangTranslationByIDUC := regionSlangTranslationsUC.NewGetByIDUC(regionSlangTranslationRepo)
	getSlangTranslationsBySlangIDUC := regionSlangTranslationsUC.NewGetBySlangIDUC(regionSlangTranslationRepo)
	updateRegionSlangTranslationUC := regionSlangTranslationsUC.NewUpdateUC(regionSlangTranslationRepo)

	//RegionTraditionsUCs
	createRegionTraditionUC := regionTraditionsUC.NewCreateUC(regionTraditionRepo)
	deleteRegionTraditionUC := regionTraditionsUC.NewDeleteUC(regionTraditionRepo)
	getRegionTraditionByIDUC := regionTraditionsUC.NewGetByIDUC(regionTraditionRepo, userActivityService, publisher)
	getTraditionsByRegionIDUC := regionTraditionsUC.NewGetByRegionUC(regionTraditionRepo)
	updateRegionTraditionUC := regionTraditionsUC.NewUpdateUC(regionTraditionRepo)

	//RegionTraditionsTranslationsUCs
	createRegionTraditionTranslationUC := regionTraditionTranslationsUC.NewCreateUC(regionTraditionTranslationRepo)
	deleteRegionTraditionTranslationUC := regionTraditionTranslationsUC.NewDeleteUC(regionTraditionTranslationRepo)
	getRegionTraditionTranslationByIDUC := regionTraditionTranslationsUC.NewGetByIDUC(regionTraditionTranslationRepo)
	getTraditionTranslationsByTraditionIDUC := regionTraditionTranslationsUC.NewGetByTraditionIDUC(regionTraditionTranslationRepo)
	updateRegionTraditionTranslationUC := regionTraditionTranslationsUC.NewUpdateUC(regionTraditionTranslationRepo)
	// Handlers
	jwtHandler := jwt.NewJwtTokenHandler(
		createTokenUC,
		findTokenUC,
		revokeJwtUC,
		getUserByIDUC,
		streakService,
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
		streakService,
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
	regionHandler := region.NewRegionHandler(
		createRegionUC,
		deleteRegionUC,
		getAllRegionUC,
		getRegionByIDUC,
		updateRegionUC,
		createMultiUC,
		getByCode,

		createRegionTranslationUC,
		deleteRegionTranslationUC,
		getRegionTranslationByIDUC,
		updateRegionTranslationUC,
		getTranslationsByRegionIDUC,
		getUserByIDUC,
	)
	regionSlangHandler := region.NewRegionSlangHandler(
		createRegionSlangUC,
		deleteRegionSlangUC,
		getRegionSlangByIDUC,
		updateRegionSlangUC,
		getSlangByRegionIDUC,

		createRegionSlangTranslationUC,
		deleteRegionSlangTranslationUC,
		getRegionSlangTranslationByIDUC,
		updateRegionSlangTranslationUC,
		getSlangTranslationsBySlangIDUC,
	)
	regionTraditionHandler := region.NewRegionTraditionHandler(
		createRegionTraditionUC,
		deleteRegionTraditionUC,
		getRegionTraditionByIDUC,
		updateRegionTraditionUC,
		getTraditionsByRegionIDUC,

		createRegionTraditionTranslationUC,
		deleteRegionTraditionTranslationUC,
		getRegionTraditionTranslationByIDUC,
		updateRegionTraditionTranslationUC,
		getTraditionTranslationsByTraditionIDUC,
	)
	achievementHandler := achievement.NewAchievementHandler(
		createAchievementUC,
		deleteAchievementUC,
		getAllAchievementUC,
		getAchievementByIDUC,
		updateAchievementUC,
	)

	userAchievementHandler := achievement.NewUserAchievementHandler(
		createUserAchievementUC,
		deleteUserAchievementUC,
		getUserAchievementByIDUC,
		getUaByUserIDUC,
		updateUserAchievementUC,
	)

	actionRuleHandler := actionRule.NewActionRuleHandler(
		createActionRuleUC,
		createMultiActionRuleUC,
		updateActionRuleUC,
		deleteActionRuleUC,
		getAllActionRuleUC,
		getActionRuleByActionUC,
	)

	userActivityHandler := userActivity.NewUserActivityHandler(userActivityService)
	wsHandler := ws.NewWebSocketManager(cfg)
	streakService.AddSubscriber(wsHandler)
	increaseUserAchievementSub.AddSubscriber(wsHandler)
	jwtHandler.AddSubscriber(wsHandler)
	return &Container{
		UserHandler:            userHandler,
		JwtHandler:             jwtHandler,
		FolkloreHandler:        folkloreHandler,
		LessonHandler:          lessonHandler,
		TestHandler:            testHandler,
		UserActivityHandler:    userActivityHandler,
		RegionHandler:          regionHandler,
		RegionSlangHandler:     regionSlangHandler,
		RegionTraditionHandler: regionTraditionHandler,
		AchievementHandler:     achievementHandler,
		UserAchievementHandler: userAchievementHandler,
		ActionRuleHandler:      actionRuleHandler,
		WebSocketHandler:       wsHandler,
	}
}
