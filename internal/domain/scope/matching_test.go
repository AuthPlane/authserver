package scope

import "testing"

func TestParse(t *testing.T) {
	ss := Parse("tools/read tools/write tools/admin")
	if ss.Len() != 3 {
		t.Errorf("Len = %d, want 3", ss.Len())
	}
	if !ss.Contains("tools/read") {
		t.Error("should contain tools/read")
	}
	if !ss.Contains("tools/write") {
		t.Error("should contain tools/write")
	}
}

func TestParseEmpty(t *testing.T) {
	ss := Parse("")
	if !ss.IsEmpty() {
		t.Error("empty string should produce empty set")
	}
	if ss == nil {
		t.Error("empty set should be non-nil")
	}
}

func TestParseWhitespace(t *testing.T) {
	ss := Parse("  tools/a   tools/b  ")
	if ss.Len() != 2 {
		t.Errorf("Len = %d, want 2", ss.Len())
	}
}

func TestParseDuplicates(t *testing.T) {
	ss := Parse("tools/a tools/a tools/b")
	if ss.Len() != 2 {
		t.Errorf("Len = %d, want 2 (deduped)", ss.Len())
	}
}

func TestNew(t *testing.T) {
	ss := New("a", "b", "c")
	if ss.Len() != 3 {
		t.Errorf("Len = %d, want 3", ss.Len())
	}
}

func TestNewSkipsEmpty(t *testing.T) {
	ss := New("a", "", "b")
	if ss.Len() != 2 {
		t.Errorf("Len = %d, want 2", ss.Len())
	}
}

func TestString(t *testing.T) {
	ss := Parse("tools/write tools/admin tools/read")
	got := ss.String()
	want := "tools/admin tools/read tools/write"
	if got != want {
		t.Errorf("String() = %q, want %q (sorted)", got, want)
	}
}

func TestStringEmpty(t *testing.T) {
	ss := Parse("")
	if got := ss.String(); got != "" {
		t.Errorf("String() = %q, want empty", got)
	}
}

func TestContains(t *testing.T) {
	ss := Parse("tools/read tools/write")
	if !ss.Contains("tools/read") {
		t.Error("should contain tools/read")
	}
	if ss.Contains("tools/admin") {
		t.Error("should not contain tools/admin")
	}
}

func TestIsSubset(t *testing.T) {
	all := Parse("tools/read tools/write tools/admin")
	sub := Parse("tools/read tools/write")
	empty := Parse("")

	if !sub.IsSubset(all) {
		t.Error("{read, write} should be subset of {read, write, admin}")
	}
	if !all.IsSubset(all) {
		t.Error("set should be subset of itself")
	}
	if all.IsSubset(sub) {
		t.Error("{read, write, admin} should NOT be subset of {read, write}")
	}
	if !empty.IsSubset(all) {
		t.Error("empty set should be subset of any set")
	}
	if !empty.IsSubset(empty) {
		t.Error("empty set should be subset of empty set")
	}
}

func TestIntersect(t *testing.T) {
	a := Parse("tools/read tools/write tools/admin")
	b := Parse("tools/write tools/admin tools/delete")
	result := a.Intersect(b)

	if result.Len() != 2 {
		t.Errorf("Len = %d, want 2", result.Len())
	}
	if !result.Contains("tools/write") || !result.Contains("tools/admin") {
		t.Error("intersection should contain write and admin")
	}
	if result.Contains("tools/read") || result.Contains("tools/delete") {
		t.Error("intersection should not contain read or delete")
	}
}

func TestIntersectDisjoint(t *testing.T) {
	a := Parse("tools/read")
	b := Parse("tools/write")
	result := a.Intersect(b)
	if !result.IsEmpty() {
		t.Error("disjoint intersection should be empty")
	}
}

func TestIntersectEmpty(t *testing.T) {
	a := Parse("tools/read")
	empty := Parse("")
	result := a.Intersect(empty)
	if !result.IsEmpty() {
		t.Error("intersection with empty should be empty")
	}
}

func TestUnion(t *testing.T) {
	a := Parse("tools/read tools/write")
	b := Parse("tools/write tools/admin")
	result := a.Union(b)
	if result.Len() != 3 {
		t.Errorf("Len = %d, want 3", result.Len())
	}
}

func TestEqual(t *testing.T) {
	a := Parse("tools/read tools/write")
	b := Parse("tools/write tools/read")
	if !a.Equal(b) {
		t.Error("sets with same elements should be equal")
	}

	c := Parse("tools/read")
	if a.Equal(c) {
		t.Error("sets with different elements should not be equal")
	}
}

func TestSlice(t *testing.T) {
	ss := Parse("tools/write tools/read")
	got := ss.Slice()
	if len(got) != 2 || got[0] != "tools/read" || got[1] != "tools/write" {
		t.Errorf("Slice() = %v, want [tools/read tools/write]", got)
	}
}
