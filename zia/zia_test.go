package zia

import "testing"

func TestHasName(t *testing.T) {
	fname := "myname"
	nname := "notfound"
	entry := PacFile{
		Name: fname,
	}
	if !HasNAme([]PacFile{entry}, fname) {
		t.Errorf("name %v not found", fname)
	}
	if HasNAme([]PacFile{entry}, nname) {
		t.Errorf("name %v found when it shouldn't", nname)
	}
}
