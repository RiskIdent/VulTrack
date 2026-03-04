package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vultrack/vultrack/internal/models"
	"github.com/vultrack/vultrack/internal/services"
)

// ReportScheduler periodically checks for due report schedules and executes them.
type ReportScheduler struct {
	scheduleService *services.ReportScheduleService
	reportService   *services.ReportService
	emailService    *services.EmailService

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewReportScheduler creates a new scheduler instance.
func NewReportScheduler(
	scheduleService *services.ReportScheduleService,
	reportService *services.ReportService,
	emailService *services.EmailService,
) *ReportScheduler {
	return &ReportScheduler{
		scheduleService: scheduleService,
		reportService:   reportService,
		emailService:    emailService,
		stopCh:          make(chan struct{}),
	}
}

// Start begins the scheduler loop. Should be called as a goroutine.
func (s *ReportScheduler) Start() {
	s.wg.Add(1)
	defer s.wg.Done()

	log.Info().Msg("Report scheduler started")
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			log.Info().Msg("Report scheduler stopped")
			return
		case <-ticker.C:
			s.checkAndRun()
		}
	}
}

// Stop signals the scheduler to stop and waits for it to finish.
func (s *ReportScheduler) Stop() {
	close(s.stopCh)
	s.wg.Wait()
}

// RunNow immediately executes a specific schedule (for manual "Run Now" trigger).
func (s *ReportScheduler) RunNow(ctx context.Context, id int64) error {
	rs, err := s.scheduleService.GetByID(ctx, id)
	if err != nil {
		return err
	}
	return s.executeSchedule(ctx, rs)
}

func (s *ReportScheduler) checkAndRun() {
	ctx := context.Background()

	due, err := s.scheduleService.GetDueSchedules(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query due report schedules")
		return
	}

	if len(due) == 0 {
		return
	}

	log.Info().Int("count", len(due)).Msg("Executing due report schedules")

	for i := range due {
		rs := &due[i]
		runErr := s.executeSchedule(ctx, rs)

		// Always mark the run (even on error) to advance next_run_at
		if markErr := s.scheduleService.MarkRun(ctx, rs.ID, rs, runErr); markErr != nil {
			log.Error().Err(markErr).Int64("scheduleId", rs.ID).Msg("Failed to mark schedule run")
		}

		if runErr != nil {
			log.Error().Err(runErr).Int64("scheduleId", rs.ID).Str("name", rs.Name).Msg("Report schedule execution failed")
		} else {
			log.Info().Int64("scheduleId", rs.ID).Str("name", rs.Name).Msg("Report schedule executed successfully")
		}
	}
}

func (s *ReportScheduler) executeSchedule(ctx context.Context, rs *models.ReportSchedule) error {
	if !s.emailService.IsEnabled() {
		return fmt.Errorf("email service is not enabled; cannot deliver scheduled report")
	}

	// Compute report period
	startDate, endDate := computePeriod(rs.PeriodType, rs.PeriodDays)

	// Build report request using the same struct the existing ReportService expects
	req := services.ReportRequest{
		ServerIDs:            rs.ServerIDs,
		GroupIDs:             rs.GroupIDs,
		StartDate:            startDate,
		EndDate:              endDate,
		ReportType:           "vulnerability_summary",
		IncludeSeverityChart: rs.IncludeSeverityChart,
		IncludeTrendChart:    rs.IncludeTrendChart,
		IncludeTopCVEs:       rs.IncludeTopCVEs,
		IncludeFullCVEList:   rs.IncludeFullCVEList,
	}

	// Generate PDF
	pdfData, err := s.reportService.GenerateVulnerabilitySummary(ctx, req)
	if err != nil {
		return fmt.Errorf("generate report: %w", err)
	}

	// Build email
	filename := fmt.Sprintf("vultrack-report-%s.pdf", endDate.Format("2006-01-02"))
	subject := fmt.Sprintf("VulTrack Report: %s", rs.Name)

	htmlBody := fmt.Sprintf(
		`<html><body>
<p>Hello,</p>
<p>Please find attached the scheduled VulTrack report <strong>%s</strong>.</p>
<p>Report period: %s to %s</p>
<p>This is an automated message from VulTrack.</p>
</body></html>`,
		rs.Name,
		startDate.Format("2006-01-02"),
		endDate.Format("2006-01-02"),
	)

	textBody := fmt.Sprintf(
		"VulTrack Report: %s\nReport period: %s to %s\n\nPlease find the report attached as PDF.",
		rs.Name,
		startDate.Format("2006-01-02"),
		endDate.Format("2006-01-02"),
	)

	attachment := services.Attachment{
		Filename:    filename,
		ContentType: "application/pdf",
		Data:        pdfData,
	}

	return s.emailService.SendEmailWithAttachments(rs.Recipients, subject, htmlBody, textBody, []services.Attachment{attachment})
}

// computePeriod returns start and end dates based on the period type.
func computePeriod(periodType string, periodDays *int) (time.Time, time.Time) {
	now := time.Now()
	endDate := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	switch periodType {
	case "last_month":
		// Full previous calendar month
		firstOfThisMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		endDate = firstOfThisMonth.AddDate(0, 0, -1) // last day of prev month
		startDate := time.Date(endDate.Year(), endDate.Month(), 1, 0, 0, 0, 0, time.UTC)
		return startDate, endDate

	case "last_week":
		// Previous calendar week (Mon-Sun)
		weekday := int(now.Weekday())
		if weekday == 0 {
			weekday = 7 // Sunday = 7
		}
		lastMonday := endDate.AddDate(0, 0, -(weekday - 1 + 7)) // Monday of last week
		lastSunday := lastMonday.AddDate(0, 0, 6)
		return lastMonday, lastSunday

	case "last_n_days":
		days := 30
		if periodDays != nil && *periodDays > 0 {
			days = *periodDays
		}
		return endDate.AddDate(0, 0, -days), endDate

	default:
		// Default: last 30 days
		return endDate.AddDate(0, 0, -30), endDate
	}
}
