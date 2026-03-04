package services

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/models"
)

// ReasonTemplateService handles reason template operations
type ReasonTemplateService struct {
	db *pgxpool.Pool
}

// NewReasonTemplateService creates a new ReasonTemplateService
func NewReasonTemplateService(db *pgxpool.Pool) *ReasonTemplateService {
	return &ReasonTemplateService{db: db}
}

// GetAll returns all active reason templates
func (s *ReasonTemplateService) GetAll(ctx context.Context) ([]models.ReasonTemplate, error) {
	query := `
		SELECT id, reason, applies_to, is_active, sort_order, created_at, updated_at
		FROM reason_templates
		WHERE is_active = true
		ORDER BY sort_order, id
	`

	rows, err := s.db.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []models.ReasonTemplate
	for rows.Next() {
		var t models.ReasonTemplate
		err := rows.Scan(
			&t.ID, &t.Reason, &t.AppliesTo, &t.IsActive, &t.SortOrder,
			&t.CreatedAt, &t.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		templates = append(templates, t)
	}

	return templates, nil
}

// GetByType returns reason templates filtered by applies_to
func (s *ReasonTemplateService) GetByType(ctx context.Context, appliesTo string) ([]models.ReasonTemplate, error) {
	query := `
		SELECT id, reason, applies_to, is_active, sort_order, created_at, updated_at
		FROM reason_templates
		WHERE is_active = true AND (applies_to = $1 OR applies_to = 'both')
		ORDER BY sort_order, id
	`

	rows, err := s.db.Query(ctx, query, appliesTo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []models.ReasonTemplate
	for rows.Next() {
		var t models.ReasonTemplate
		err := rows.Scan(
			&t.ID, &t.Reason, &t.AppliesTo, &t.IsActive, &t.SortOrder,
			&t.CreatedAt, &t.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		templates = append(templates, t)
	}

	return templates, nil
}

// Create adds a new reason template
func (s *ReasonTemplateService) Create(ctx context.Context, t *models.ReasonTemplate) (*models.ReasonTemplate, error) {
	query := `
		INSERT INTO reason_templates (reason, applies_to, is_active, sort_order)
		VALUES ($1, $2, $3, $4)
		RETURNING id, reason, applies_to, is_active, sort_order, created_at, updated_at
	`

	var result models.ReasonTemplate
	err := s.db.QueryRow(ctx, query, t.Reason, t.AppliesTo, t.IsActive, t.SortOrder).Scan(
		&result.ID, &result.Reason, &result.AppliesTo, &result.IsActive, &result.SortOrder,
		&result.CreatedAt, &result.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// Update modifies an existing reason template
func (s *ReasonTemplateService) Update(ctx context.Context, t *models.ReasonTemplate) (*models.ReasonTemplate, error) {
	query := `
		UPDATE reason_templates
		SET reason = $2, applies_to = $3, is_active = $4, sort_order = $5, updated_at = NOW()
		WHERE id = $1
		RETURNING id, reason, applies_to, is_active, sort_order, created_at, updated_at
	`

	var result models.ReasonTemplate
	err := s.db.QueryRow(ctx, query, t.ID, t.Reason, t.AppliesTo, t.IsActive, t.SortOrder).Scan(
		&result.ID, &result.Reason, &result.AppliesTo, &result.IsActive, &result.SortOrder,
		&result.CreatedAt, &result.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// Delete removes a reason template (soft delete by setting is_active = false)
func (s *ReasonTemplateService) Delete(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `UPDATE reason_templates SET is_active = false, updated_at = NOW() WHERE id = $1`, id)
	return err
}
