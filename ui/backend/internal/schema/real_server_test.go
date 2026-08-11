package schema

import (
	"bufio"
	"os"
	"testing"
)

// 실제 OpenLDAP 2.6.14 서버가 cn=Subschema 로 내보내는 objectClasses 정의
// 전량을 파싱한다. 파서를 RFC 예문으로만 검증하면 실서버가 내보내는 형태
// (DESC 안의 따옴표, X-ORIGIN, 괄호 없는 단일 MUST 등)에서 깨질 수 있고,
// 그러면 스키마 인식 폼이 실환경에서만 실패한다.
func TestParseEveryDefinitionFromRealServer(t *testing.T) {
	f, err := os.Open("testdata/objectclasses-2.6.14.txt")
	if err != nil {
		t.Fatalf("captured server schema missing: %v", err)
	}
	defer f.Close()

	var classes []*ObjectClass
	n, fails := 0, 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		n++
		oc, err := ParseObjectClass(line)
		if err != nil {
			fails++
			t.Errorf("parse failed:\n  %s\n  err: %v", line, err)
			continue
		}
		classes = append(classes, oc)
	}
	t.Logf("parsed %d/%d definitions", n-fails, n)
	s := NewSchema(classes)

	must, may := s.EffectiveAttributes([]string{"inetOrgPerson"})
	t.Logf("inetOrgPerson MUST=%v", must)
	t.Logf("inetOrgPerson MAY count=%d", len(may))
	if len(must) == 0 {
		t.Error("inetOrgPerson resolved no MUST attributes — SUP chain merge is broken")
	}
	m2, _ := s.EffectiveAttributes([]string{"groupOfNames"})
	t.Logf("groupOfNames MUST=%v", m2)
}
