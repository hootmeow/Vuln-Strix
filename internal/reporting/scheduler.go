package reporting

import (
	"log"
	"time"
)

type Scheduler struct {
	Mailer   *Mailer
	LastSent time.Time
}

func NewScheduler(mailer *Mailer) *Scheduler {
	return &Scheduler{
		Mailer: mailer,
	}
}

func (s *Scheduler) Start() {
	if !s.Mailer.Config.Enabled {
		log.Println("Reporting Scheduler: Disabled in config.")
		return
	}

	log.Println("Reporting Scheduler: Started. Checking for Monday 9:00 AM schedule...")

	// Check every minute
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for t := range ticker.C {
			s.checkSchedule(t)
		}
	}()
}

func (s *Scheduler) checkSchedule(now time.Time) {
	// Schedule: Monday at 09:xx AM
	if now.Weekday() == time.Monday && now.Hour() == 9 {

		// Check if already sent today (to prevent spamming during the 9th hour)
		if s.LastSent.Year() == now.Year() && s.LastSent.Month() == now.Month() && s.LastSent.Day() == now.Day() {
			return
		}

		log.Println("Reporting Scheduler: Triggering Weekly Report...")
		err := s.Mailer.SendDeltaReport()
		if err != nil {
			log.Printf("Reporting Scheduler: Failed to send report: %v", err)
			// Don't update LastSent so it tries again next minute?
			// Or maybe wait? Let's try again next minute (default behavior if we don't update LastSent)
			// But if it fails consistently, we might spam logs.
			// Let's rely on transient failure retry.
		} else {
			s.LastSent = now
			log.Println("Reporting Scheduler: Report Sent Successfully.")
		}
	}
}

// For manual testing/triggering
func (s *Scheduler) TriggerNow() error {
	return s.Mailer.SendDeltaReport()
}
