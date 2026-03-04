package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vultrack/vultrack/internal/models"
)

// ReportScheduleService manages CRUD and scheduling logic for report_schedules.
type ReportScheduleService struct {
	db *pgxpool.Pool
}

func NewReportScheduleService(db *pgxpool.Pool) *ReportScheduleService {
	return &ReportScheduleService{db: db}
}

// GetAll returns all report schedules ordered by created_at desc.
func (s *ReportScheduleService) GetAll(ctx context.Context) ([]models.ReportSchedule, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, name,
			schedule_type, interval_value, day_of_week, week_of_month, day_of_month,
			time_hour, time_minute, timezone,
			server_ids, group_ids,
			period_type, period_days,
			include_severity_chart, include_trend_chart, include_top_cves, include_full_cve_list,
			recipients,
			enabled, last_run_at, next_run_at, COALESCE(last_error, ''),
			created_at, updated_at
		FROM report_schedules
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("query report_schedules: %w", err)
	}
	defer rows.Close()

	var schedules []models.ReportSchedule
	for rows.Next() {
		rs, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		schedules = append(schedules, rs)
	}
	return schedules, nil
}

// GetByID returns a single report schedule.
func (s *ReportScheduleService) GetByID(ctx context.Context, id int64) (*models.ReportSchedule, error) {
	row := s.db.QueryRow(ctx, `
		SELECT id, name,
			schedule_type, interval_value, day_of_week, week_of_month, day_of_month,
			time_hour, time_minute, timezone,
			server_ids, group_ids,
			period_type, period_days,
			include_severity_chart, include_trend_chart, include_top_cves, include_full_cve_list,
			recipients,
			enabled, last_run_at, next_run_at, COALESCE(last_error, ''),
			created_at, updated_at
		FROM report_schedules
		WHERE id = $1
	`, id)

	rs, err := scanScheduleRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("report schedule %d not found", id)
		}
		return nil, fmt.Errorf("get report schedule %d: %w", id, err)
	}
	return &rs, nil
}

// Create inserts a new report schedule and computes its next_run_at.
func (s *ReportScheduleService) Create(ctx context.Context, rs *models.ReportSchedule) error {
	nextRun := CalculateNextRun(rs, time.Now())
	rs.NextRunAt = &nextRun

	err := s.db.QueryRow(ctx, `
		INSERT INTO report_schedules (
			name, schedule_type, interval_value, day_of_week, week_of_month, day_of_month,
			time_hour, time_minute, timezone,
			server_ids, group_ids,
			period_type, period_days,
			include_severity_chart, include_trend_chart, include_top_cves, include_full_cve_list,
			recipients, enabled, next_run_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
		RETURNING id, created_at, updated_at
	`,
		rs.Name, rs.ScheduleType, rs.IntervalValue, rs.DayOfWeek, rs.WeekOfMonth, rs.DayOfMonth,
		rs.TimeHour, rs.TimeMinute, rs.Timezone,
		rs.ServerIDs, rs.GroupIDs,
		rs.PeriodType, rs.PeriodDays,
		rs.IncludeSeverityChart, rs.IncludeTrendChart, rs.IncludeTopCVEs, rs.IncludeFullCVEList,
		rs.Recipients, rs.Enabled, rs.NextRunAt,
	).Scan(&rs.ID, &rs.CreatedAt, &rs.UpdatedAt)

	if err != nil {
		return fmt.Errorf("insert report schedule: %w", err)
	}
	return nil
}

// Update modifies an existing report schedule and recomputes next_run_at.
func (s *ReportScheduleService) Update(ctx context.Context, rs *models.ReportSchedule) error {
	nextRun := CalculateNextRun(rs, time.Now())
	rs.NextRunAt = &nextRun

	_, err := s.db.Exec(ctx, `
		UPDATE report_schedules SET
			name = $2, schedule_type = $3, interval_value = $4,
			day_of_week = $5, week_of_month = $6, day_of_month = $7,
			time_hour = $8, time_minute = $9, timezone = $10,
			server_ids = $11, group_ids = $12,
			period_type = $13, period_days = $14,
			include_severity_chart = $15, include_trend_chart = $16,
			include_top_cves = $17, include_full_cve_list = $18,
			recipients = $19, enabled = $20, next_run_at = $21,
			updated_at = NOW()
		WHERE id = $1
	`,
		rs.ID,
		rs.Name, rs.ScheduleType, rs.IntervalValue,
		rs.DayOfWeek, rs.WeekOfMonth, rs.DayOfMonth,
		rs.TimeHour, rs.TimeMinute, rs.Timezone,
		rs.ServerIDs, rs.GroupIDs,
		rs.PeriodType, rs.PeriodDays,
		rs.IncludeSeverityChart, rs.IncludeTrendChart,
		rs.IncludeTopCVEs, rs.IncludeFullCVEList,
		rs.Recipients, rs.Enabled, rs.NextRunAt,
	)
	if err != nil {
		return fmt.Errorf("update report schedule %d: %w", rs.ID, err)
	}
	return nil
}

// Delete removes a report schedule.
func (s *ReportScheduleService) Delete(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM report_schedules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete report schedule %d: %w", id, err)
	}
	return nil
}

// SetEnabled toggles a report schedule and recomputes next_run_at if enabling.
func (s *ReportScheduleService) SetEnabled(ctx context.Context, id int64, enabled bool) error {
	if enabled {
		// Need schedule info to compute next run
		rs, err := s.GetByID(ctx, id)
		if err != nil {
			return err
		}
		nextRun := CalculateNextRun(rs, time.Now())
		_, err = s.db.Exec(ctx,
			`UPDATE report_schedules SET enabled = $2, next_run_at = $3, updated_at = NOW() WHERE id = $1`,
			id, enabled, nextRun,
		)
		return err
	}
	_, err := s.db.Exec(ctx,
		`UPDATE report_schedules SET enabled = $2, next_run_at = NULL, updated_at = NOW() WHERE id = $1`,
		id, enabled,
	)
	return err
}

// GetDueSchedules returns all enabled schedules whose next_run_at <= now.
func (s *ReportScheduleService) GetDueSchedules(ctx context.Context) ([]models.ReportSchedule, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, name,
			schedule_type, interval_value, day_of_week, week_of_month, day_of_month,
			time_hour, time_minute, timezone,
			server_ids, group_ids,
			period_type, period_days,
			include_severity_chart, include_trend_chart, include_top_cves, include_full_cve_list,
			recipients,
			enabled, last_run_at, next_run_at, COALESCE(last_error, ''),
			created_at, updated_at
		FROM report_schedules
		WHERE enabled = true AND next_run_at IS NOT NULL AND next_run_at <= NOW()
	`)
	if err != nil {
		return nil, fmt.Errorf("query due schedules: %w", err)
	}
	defer rows.Close()

	var schedules []models.ReportSchedule
	for rows.Next() {
		rs, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		schedules = append(schedules, rs)
	}
	return schedules, nil
}

// MarkRun updates last_run_at, computes next_run_at, and optionally stores an error.
func (s *ReportScheduleService) MarkRun(ctx context.Context, id int64, rs *models.ReportSchedule, runErr error) error {
	now := time.Now()
	nextRun := CalculateNextRun(rs, now)
	errMsg := ""
	if runErr != nil {
		errMsg = runErr.Error()
	}

	_, err := s.db.Exec(ctx, `
		UPDATE report_schedules
		SET last_run_at = $2, next_run_at = $3, last_error = $4, updated_at = NOW()
		WHERE id = $1
	`, id, now, nextRun, errMsg)
	return err
}

// CalculateNextRun computes the next run time after 'after' based on the schedule definition.
func CalculateNextRun(rs *models.ReportSchedule, after time.Time) time.Time {
	loc, err := time.LoadLocation(rs.Timezone)
	if err != nil {
		loc = time.UTC
	}
	now := after.In(loc)

	switch rs.ScheduleType {
	case "weekly":
		return nextWeekly(now, loc, rs.TimeHour, rs.TimeMinute, derefInt(rs.DayOfWeek, 1), rs.IntervalValue)
	case "monthly_dom":
		return nextMonthlyDOM(now, loc, rs.TimeHour, rs.TimeMinute, derefInt(rs.DayOfMonth, 1), rs.IntervalValue)
	case "monthly_dow":
		return nextMonthlyDOW(now, loc, rs.TimeHour, rs.TimeMinute, derefInt(rs.DayOfWeek, 1), derefInt(rs.WeekOfMonth, 1), rs.IntervalValue)
	default:
		// Fallback: next day at the configured time
		t := time.Date(now.Year(), now.Month(), now.Day()+1, rs.TimeHour, rs.TimeMinute, 0, 0, loc)
		return t.UTC()
	}
}

// nextWeekly returns the next occurrence of a weekly schedule.
func nextWeekly(now time.Time, loc *time.Location, hour, minute, dow, interval int) time.Time {
	targetDay := time.Weekday(dow)

	// Start from the current day at the target time
	candidate := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, loc)

	// Find the next matching weekday
	daysUntil := int(targetDay) - int(candidate.Weekday())
	if daysUntil < 0 {
		daysUntil += 7
	}
	candidate = candidate.AddDate(0, 0, daysUntil)

	// If candidate is in the past (or right now), move forward by interval weeks
	if !candidate.After(now) {
		candidate = candidate.AddDate(0, 0, 7*interval)
	}

	return candidate.UTC()
}

// nextMonthlyDOM returns the next day-of-month occurrence.
func nextMonthlyDOM(now time.Time, loc *time.Location, hour, minute, dom, interval int) time.Time {
	// Clamp day of month
	if dom > 28 {
		dom = 28 // safe for all months
	}

	candidate := time.Date(now.Year(), now.Month(), dom, hour, minute, 0, 0, loc)
	if !candidate.After(now) {
		// Move forward by interval months
		candidate = candidate.AddDate(0, interval, 0)
	}

	return candidate.UTC()
}

// nextMonthlyDOW returns the next Nth weekday-of-month occurrence (e.g. 2nd Tuesday).
func nextMonthlyDOW(now time.Time, loc *time.Location, hour, minute, dow, weekNum, interval int) time.Time {
	// Try current month first
	candidate := nthWeekdayOfMonth(now.Year(), now.Month(), time.Weekday(dow), weekNum, hour, minute, loc)
	if candidate.After(now) {
		return candidate.UTC()
	}

	// Move forward by interval months
	y, m, _ := now.Date()
	nextMonth := time.Date(y, m+time.Month(interval), 1, 0, 0, 0, 0, loc)
	candidate = nthWeekdayOfMonth(nextMonth.Year(), nextMonth.Month(), time.Weekday(dow), weekNum, hour, minute, loc)
	return candidate.UTC()
}

// nthWeekdayOfMonth finds the Nth occurrence of a weekday in a given month.
func nthWeekdayOfMonth(year int, month time.Month, weekday time.Weekday, n int, hour, minute int, loc *time.Location) time.Time {
	// Start at the 1st of the month
	first := time.Date(year, month, 1, hour, minute, 0, 0, loc)

	// Find first occurrence of the target weekday
	daysUntil := int(weekday) - int(first.Weekday())
	if daysUntil < 0 {
		daysUntil += 7
	}
	firstOccurrence := first.AddDate(0, 0, daysUntil)

	// Jump to the Nth occurrence
	return firstOccurrence.AddDate(0, 0, (n-1)*7)
}

// scanSchedule scans a row from pgx.Rows into a ReportSchedule.
func scanSchedule(rows pgx.Rows) (models.ReportSchedule, error) {
	var rs models.ReportSchedule
	err := rows.Scan(
		&rs.ID, &rs.Name,
		&rs.ScheduleType, &rs.IntervalValue, &rs.DayOfWeek, &rs.WeekOfMonth, &rs.DayOfMonth,
		&rs.TimeHour, &rs.TimeMinute, &rs.Timezone,
		&rs.ServerIDs, &rs.GroupIDs,
		&rs.PeriodType, &rs.PeriodDays,
		&rs.IncludeSeverityChart, &rs.IncludeTrendChart, &rs.IncludeTopCVEs, &rs.IncludeFullCVEList,
		&rs.Recipients,
		&rs.Enabled, &rs.LastRunAt, &rs.NextRunAt, &rs.LastError,
		&rs.CreatedAt, &rs.UpdatedAt,
	)
	if err != nil {
		return rs, fmt.Errorf("scan report_schedule: %w", err)
	}
	if rs.ServerIDs == nil {
		rs.ServerIDs = []int64{}
	}
	if rs.GroupIDs == nil {
		rs.GroupIDs = []int64{}
	}
	if rs.Recipients == nil {
		rs.Recipients = []string{}
	}
	return rs, nil
}

// scanScheduleRow scans a single pgx.Row into a ReportSchedule.
func scanScheduleRow(row pgx.Row) (models.ReportSchedule, error) {
	var rs models.ReportSchedule
	err := row.Scan(
		&rs.ID, &rs.Name,
		&rs.ScheduleType, &rs.IntervalValue, &rs.DayOfWeek, &rs.WeekOfMonth, &rs.DayOfMonth,
		&rs.TimeHour, &rs.TimeMinute, &rs.Timezone,
		&rs.ServerIDs, &rs.GroupIDs,
		&rs.PeriodType, &rs.PeriodDays,
		&rs.IncludeSeverityChart, &rs.IncludeTrendChart, &rs.IncludeTopCVEs, &rs.IncludeFullCVEList,
		&rs.Recipients,
		&rs.Enabled, &rs.LastRunAt, &rs.NextRunAt, &rs.LastError,
		&rs.CreatedAt, &rs.UpdatedAt,
	)
	if err != nil {
		return rs, err
	}
	if rs.ServerIDs == nil {
		rs.ServerIDs = []int64{}
	}
	if rs.GroupIDs == nil {
		rs.GroupIDs = []int64{}
	}
	if rs.Recipients == nil {
		rs.Recipients = []string{}
	}
	return rs, nil
}

func derefInt(p *int, def int) int {
	if p != nil {
		return *p
	}
	return def
}
