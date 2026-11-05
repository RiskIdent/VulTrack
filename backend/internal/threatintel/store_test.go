package threatintel_test

// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vultrack/vultrack/internal/testdb"
	"github.com/vultrack/vultrack/internal/threatintel"
)

func date(s string) *time.Time {
	t, _ := time.Parse("2006-01-02", s)
	return &t
}

func TestStoreKEV(t *testing.T) {
	pool, ctx := testdb.Setup(t, "threatintel_kev_tests")

	first := []threatintel.KEVEntry{
		{CVEID: "CVE-2026-0001", VendorProject: "A", DateAdded: date("2026-01-01"), KnownRansomwareUse: true},
		{CVEID: "CVE-2026-0002", VendorProject: "B", DateAdded: date("2026-02-01")},
		{CVEID: "CVE-2026-0003", VendorProject: "C", DateAdded: date("2026-03-01")},
	}
	if err := threatintel.StoreKEV(ctx, pool, first); err != nil {
		t.Fatalf("StoreKEV: %v", err)
	}
	var before time.Time
	if err := pool.QueryRow(ctx, `SELECT updated_at FROM kev_entries WHERE cve_id = 'CVE-2026-0001'`).Scan(&before); err != nil {
		t.Fatalf("read: %v", err)
	}

	// Second sync: 0002 delisted, 0003 changed, 0004 new, 0001 unchanged.
	second := []threatintel.KEVEntry{
		first[0],
		{CVEID: "CVE-2026-0003", VendorProject: "C2", DateAdded: date("2026-03-01")},
		{CVEID: "CVE-2026-0004", VendorProject: "D", DateAdded: date("2026-04-01")},
	}
	time.Sleep(10 * time.Millisecond)
	if err := threatintel.StoreKEV(ctx, pool, second); err != nil {
		t.Fatalf("StoreKEV: %v", err)
	}

	rows, err := pool.Query(ctx, `SELECT cve_id, vendor_project, known_ransomware_use, updated_at FROM kev_entries ORDER BY cve_id`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var id, vendor string
		var ransomware bool
		var updated time.Time
		if err := rows.Scan(&id, &vendor, &ransomware, &updated); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, fmt.Sprintf("%s/%s/%t", id, vendor, ransomware))
		if id == "CVE-2026-0001" && !updated.Equal(before) {
			t.Errorf("unchanged entry was rewritten (updated_at %v -> %v)", before, updated)
		}
	}
	want := "CVE-2026-0001/A/true CVE-2026-0003/C2/false CVE-2026-0004/D/false"
	if strings.Join(got, " ") != want {
		t.Errorf("kev_entries = %v, want %s", got, want)
	}
}

func epssFile(rows int) string {
	var b strings.Builder
	b.WriteString("#model_version:v2026.06.15,score_date:2026-11-04T12:03:12Z\ncve,epss,percentile\n")
	for i := 0; i < rows; i++ {
		fmt.Fprintf(&b, "CVE-2026-%05d,0.%05d,0.50000\n", i, i%100000)
	}
	return b.String()
}

func TestStoreEPSS(t *testing.T) {
	pool, ctx := testdb.Setup(t, "threatintel_epss_tests")

	store := func(content string, minRows int) (int, error) {
		er, err := threatintel.NewEPSSReader(strings.NewReader(content))
		if err != nil {
			t.Fatalf("NewEPSSReader: %v", err)
		}
		return threatintel.StoreEPSS(ctx, pool, er, minRows)
	}
	count := func() int {
		var n int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM epss_scores`).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}

	if n, err := store(epssFile(500), 100); err != nil || n != 500 || count() != 500 {
		t.Fatalf("first load: n=%d err=%v count=%d", n, err, count())
	}

	t.Run("a full replacement drops scores no longer listed", func(t *testing.T) {
		if n, err := store(epssFile(300), 100); err != nil || n != 300 || count() != 300 {
			t.Errorf("n=%d err=%v count=%d", n, err, count())
		}
	})

	t.Run("a file below the floor changes nothing", func(t *testing.T) {
		if _, err := store(epssFile(50), 100); err == nil {
			t.Error("expected an error")
		}
		if count() != 300 {
			t.Errorf("count = %d, want the previous 300", count())
		}
	})

	t.Run("a malformed row changes nothing", func(t *testing.T) {
		if _, err := store(epssFile(300)+"CVE-2026-99999,7,0.5\n", 100); err == nil {
			t.Error("expected an error")
		}
		if count() != 300 {
			t.Errorf("count = %d, want the previous 300", count())
		}
	})

	t.Run("score date and values are stored", func(t *testing.T) {
		var epss, pct float64
		var day time.Time
		err := pool.QueryRow(ctx, `SELECT epss::float8, percentile::float8, score_date FROM epss_scores WHERE cve_id = 'CVE-2026-00042'`).Scan(&epss, &pct, &day)
		if err != nil || epss != 0.00042 || pct != 0.5 || day.Format("2006-01-02") != "2026-11-04" {
			t.Errorf("row = %v %v %v err=%v", epss, pct, day, err)
		}
	})
}
