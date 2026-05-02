package app

import (
	_ "DaraTilBackendV2/docs"
	"DaraTilBackendV2/internal/config"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/service/achievement"
	"DaraTilBackendV2/internal/presentation/http/service/actionRule"
	"DaraTilBackendV2/internal/presentation/http/service/assistant"
	"DaraTilBackendV2/internal/presentation/http/service/dictionary"
	"DaraTilBackendV2/internal/presentation/http/service/folklore"
	"DaraTilBackendV2/internal/presentation/http/service/leaderboard"
	"DaraTilBackendV2/internal/presentation/http/service/lesson"
	"DaraTilBackendV2/internal/presentation/http/service/region"
	"DaraTilBackendV2/internal/presentation/http/service/test"
	"DaraTilBackendV2/internal/presentation/http/service/user"
	"DaraTilBackendV2/internal/presentation/http/service/userActivity"
	"DaraTilBackendV2/internal/presentation/http/service/userProfile"
	"context"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	"github.com/swaggo/gin-swagger"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

type App struct {
	cfg       *config.Config
	container *Container
	router    *gin.Engine
}

func New(cfg *config.Config) *App {
	return &App{
		cfg:       cfg,
		container: NewContainer(cfg),
		router:    gin.Default(),
	}
}

func (a *App) setupMiddleware() {
	a.router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173", "http://localhost:8080"},
		AllowCredentials: true,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
		AllowHeaders:     []string{"Authorization", "Content-Type", "X-CSRF-Token"},
		ExposeHeaders:    []string{"Content-Length"},
		MaxAge:           12 * time.Hour,
	}))
}

func (a *App) setupRoutes() {
	api := a.router.Group("/api")
	authLimiter := middleware.NewIPRateLimiter(rate.Every(time.Minute/20), 20*time.Minute, 10)
	generalLimiter := middleware.NewIPRateLimiter(rate.Every(time.Minute/60), 20*time.Minute, 20)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	authLimiter.StartCleanup(ctx, 5*time.Minute)

	//Auth
	auth := api.Group("/auth")
	authSecure := api.Group("/auth")
	auth.Use(middleware.RateLimiter(authLimiter))
	authSecure.Use(middleware.AuthMiddleware(a.cfg))
	authSecure.Use(middleware.RateLimiter(authLimiter))

	//user
	userRoute := api.Group("/user")
	userSecure := api.Group("/user")
	userSecure.Use(middleware.AuthMiddleware(a.cfg))
	userSecure.Use(middleware.RateLimiter(generalLimiter))

	user.RegisterAuthRoutes(
		auth,
		a.container.UserHandler,
		a.container.JwtHandler,
	)
	user.RegisterAuthProtectedRoutes(authSecure, a.container.JwtHandler)
	user.RegisterRoutes(userRoute, a.container.UserHandler)
	user.RegisterProtectedRoutes(userSecure, a.container.UserHandler)

	//Folklore
	folk := api.Group("/folklore")
	folk.Use(middleware.AuthMiddleware(a.cfg))
	folk.Use(middleware.RateLimiter(generalLimiter))
	folklore.RegisterRoutes(folk, a.container.FolkloreHandler)

	//Lesson
	lessonRoute := api.Group("/lesson")
	lessonRoute.Use(middleware.AuthMiddleware(a.cfg))
	lessonRoute.Use(middleware.RateLimiter(generalLimiter))
	lesson.RegisterRoutes(lessonRoute, a.container.LessonHandler)

	//Test
	testRoute := api.Group("/test")
	testRoute.Use(middleware.AuthMiddleware(a.cfg))
	testRoute.Use(middleware.RateLimiter(generalLimiter))

	test.RegisterProtectedTestRoutes(testRoute, a.container.TestHandler)

	//Achievements
	achievementRoute := api.Group("/achievement")
	achievementRoute.Use(middleware.AuthMiddleware(a.cfg))
	achievementRoute.Use(middleware.RateLimiter(generalLimiter))
	achievement.RegisterAchievementRoutes(achievementRoute, a.container.AchievementHandler)

	//UserAchievements
	userAchievementRoute := api.Group("/userAchievements")
	userAchievementRoute.Use(middleware.AuthMiddleware(a.cfg))
	userAchievementRoute.Use(middleware.RequireRole("admin"))
	userAchievementRoute.Use(middleware.RateLimiter(generalLimiter))
	achievement.RegisterUserAchievementRoutes(userAchievementRoute, a.container.UserAchievementHandler)

	//UserActivities
	activityRoute := api.Group("/activity")
	activityRoute.Use(middleware.AuthMiddleware(a.cfg))
	activityRoute.Use(middleware.RateLimiter(generalLimiter))
	userActivity.RegisterRoutes(activityRoute, a.container.UserActivityHandler)

	//region
	regionRoute := api.Group("/region")
	regionRoute.Use(middleware.AuthMiddleware(a.cfg))
	regionRoute.Use(middleware.RateLimiter(generalLimiter))
	region.RegisterRoutes(regionRoute, a.container.RegionHandler)
	region.RegisterSlangRoutes(regionRoute, a.container.RegionSlangHandler)
	region.RegisterTraditionRoutes(regionRoute, a.container.RegionTraditionHandler)

	//actionRules
	actionRulesRoute := api.Group("/actionRules")
	actionRulesRoute.Use(middleware.AuthMiddleware(a.cfg))
	actionRulesRoute.Use(middleware.RequireRole("admin"))
	actionRulesRoute.Use(middleware.RateLimiter(generalLimiter))
	actionRule.RegisterRoutes(actionRulesRoute, a.container.ActionRuleHandler)

	//Assistant
	assistantRoute := api.Group("/assistant")
	assistantRoute.Use(middleware.AuthMiddleware(a.cfg))
	assistantRoute.Use(middleware.RateLimiter(generalLimiter))
	assistant.RegisterRoutes(assistantRoute, a.container.Assistant)

	//UserProfile
	userProfileRoute := api.Group("/userProfile")
	userProfileRoute.Use(middleware.AuthMiddleware(a.cfg))
	userProfileRoute.Use(middleware.RateLimiter(generalLimiter))
	userProfile.RegisterRoutes(userProfileRoute, a.container.UserProfileHandler)

	//Dictionary
	dictionaryRoute := api.Group("dictionary")
	dictionaryRoute.Use(middleware.AuthMiddleware(a.cfg))
	dictionaryRoute.Use(middleware.RateLimiter(generalLimiter))
	dictionary.RegisterRoutes(dictionaryRoute, a.container.DictionaryHandler)
	//Leaderboard
	leaderboardRoute := api.Group("/leaderboard")
	leaderboardRoute.Use(middleware.AuthMiddleware(a.cfg))
	leaderboardRoute.Use(middleware.RateLimiter(generalLimiter))
	leaderboard.RegisterRoutes(leaderboardRoute, a.container.LeaderboardHandler)

	api.GET("/ws", middleware.AuthMiddleware(a.cfg), a.container.WebSocketHandler.ServeWS)
	api.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

}

func (a *App) Run() {
	logger.Init(true)
	a.setupMiddleware()
	a.setupRoutes()

	logger.Info("App started:", zap.String("port", a.cfg.Server.Port))
	_ = a.router.Run(":" + a.cfg.Server.Port)
}
