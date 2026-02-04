package storage

import (
	"time"

	"github.com/hootmeow/Vuln-Strix/internal/models"
)

func (s *SQLiteStore) CreateMetricSnapshot(snapshot *models.MetricSnapshot) error {
	return s.db.Create(snapshot).Error
}

func (s *SQLiteStore) GetMetricSnapshots(metricType string, days int) ([]models.MetricSnapshot, error) {
	var snapshots []models.MetricSnapshot
	since := time.Now().AddDate(0, 0, -days)
	err := s.db.Where("metric_type = ? AND snapshot_date >= ?", metricType, since).
		Order("snapshot_date asc").Find(&snapshots).Error
	return snapshots, err
}

func (s *SQLiteStore) GetVelocityMetrics(periodDays int, count int) ([]VelocityMetric, error) {
	var metrics []VelocityMetric
	now := time.Now()

	for i := count - 1; i >= 0; i-- {
		end := now.AddDate(0, 0, -i*periodDays)
		start := end.AddDate(0, 0, -periodDays)

		var newCount int64
		s.db.Model(&models.Finding{}).Where("first_seen >= ? AND first_seen < ?", start, end).Count(&newCount)

		var fixedCount int64
		s.db.Model(&models.Finding{}).Where("fixed_at >= ? AND fixed_at < ? AND status = ?", start, end, "Fixed").Count(&fixedCount)

		metrics = append(metrics, VelocityMetric{
			PeriodStart: start,
			PeriodEnd:   end,
			NewCount:    int(newCount),
			FixedCount:  int(fixedCount),
			NetChange:   int(newCount) - int(fixedCount),
		})
	}
	return metrics, nil
}

func (s *SQLiteStore) GetMTTRTrend(days int) ([]MTTRTrend, error) {
	var trends []MTTRTrend
	since := time.Now().AddDate(0, 0, -days)

	var findings []models.Finding
	s.db.Preload("Vuln").Where("status = ? AND fixed_at >= ?", "Fixed", since).Find(&findings)

	// Group by week and severity
	weekData := make(map[string]map[string][]float64)
	for _, f := range findings {
		week := f.FixedAt.Truncate(7 * 24 * time.Hour).Format("2006-01-02")
		if weekData[week] == nil {
			weekData[week] = make(map[string][]float64)
		}
		mttr := f.FixedAt.Sub(f.FirstSeen).Hours() / 24
		weekData[week][f.Vuln.Severity] = append(weekData[week][f.Vuln.Severity], mttr)
	}

	for week, severities := range weekData {
		date, _ := time.Parse("2006-01-02", week)
		for sev, values := range severities {
			var sum float64
			for _, v := range values {
				sum += v
			}
			trends = append(trends, MTTRTrend{
				Date:     date,
				Severity: sev,
				MTTR:     sum / float64(len(values)),
			})
		}
	}
	return trends, nil
}

func (s *SQLiteStore) CollectDailySnapshot() error {
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	// Open findings by severity
	for _, sev := range []string{"Critical", "High", "Medium", "Low"} {
		var count int64
		s.db.Model(&models.Finding{}).
			Joins("JOIN vulnerabilities ON vulnerabilities.id = findings.vulnerability_id").
			Where("findings.status = ? AND vulnerabilities.severity = ?", "Open", sev).
			Count(&count)

		s.CreateMetricSnapshot(&models.MetricSnapshot{
			SnapshotDate: today,
			MetricType:   "open_findings",
			Dimension:    sev,
			Value:        float64(count),
		})
	}

	// Total open findings
	var totalOpen int64
	s.db.Model(&models.Finding{}).Where("status = ?", "Open").Count(&totalOpen)
	s.CreateMetricSnapshot(&models.MetricSnapshot{
		SnapshotDate: today,
		MetricType:   "open_findings",
		Dimension:    "Total",
		Value:        float64(totalOpen),
	})

	return nil
}
