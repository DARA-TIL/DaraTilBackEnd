package scheduler

import (
	"DaraTilBackendV2/internal/application/usecases/timeEventUC"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"
	"log"
	"time"

	"github.com/robfig/cron/v3"
)

type CronScheduler struct {
	cron                  *cron.Cron
	updateDueTimeEventsUC *timeEventUC.UpdateDueTimeEventsUC
	startWeeklyEventUC    *timeEventUC.StartWeeklyEventUC
}

func NewCronScheduler(
	updateDueTimeEventsUC *timeEventUC.UpdateDueTimeEventsUC,
	startWeeklyEventUC *timeEventUC.StartWeeklyEventUC,
) *CronScheduler {
	loc, err := time.LoadLocation("Asia/Qyzylorda")
	if err != nil {
		log.Fatal(err)
	}
	c := cron.New(
		cron.WithLocation(loc),
		cron.WithChain(
			cron.SkipIfStillRunning(cron.DefaultLogger),
			cron.Recover(cron.DefaultLogger),
		),
	)
	return &CronScheduler{
		cron:                  c,
		updateDueTimeEventsUC: updateDueTimeEventsUC,
		startWeeklyEventUC:    startWeeklyEventUC,
	}
}

func (s *CronScheduler) RegisterJobs() error {
	_, err := s.cron.AddFunc("@every 1h", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		logger.Info("Starting cron job for updateDueTimeEvent")
		if err := s.updateDueTimeEventsUC.Execute(ctx); err != nil {
			log.Printf("failed to start available time events: %v", err)
		}
	})
	if err != nil {
		return err
	}
	_, err = s.cron.AddFunc("0 0 * * *", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		logger.Info("Starting cron job for startWeeklyEvent")

		if err := s.startWeeklyEventUC.Execute(ctx); err != nil {
			log.Printf("failed to start weekly events: %v", err)
		}
	})
	if err != nil {
		return err
	}
	return nil
}
func (s *CronScheduler) Start() {
	s.cron.Start()
}

func (s *CronScheduler) Stop(ctx context.Context) {
	stopCtx := s.cron.Stop()

	select {
	case <-stopCtx.Done():
	case <-ctx.Done():
	}
}
