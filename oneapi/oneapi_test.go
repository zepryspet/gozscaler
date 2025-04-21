package oneapi

import "testing"

func TestValidateVanity(t *testing.T) {
	valid := []string{
		"z-234561",
		"glastra",
		"abd",
	}
	invalid := []string{
		"vanity-admin",
		"glastra.zslogin",
		"https://vanity.zslogin.net",
	}
	for _, v := range valid {
		if validateVanity(v) != nil {
			t.Errorf("validateVanity() failed, vanity validation failed: %s", v)
		}
	}
	for _, v := range invalid {
		if validateVanity(v) == nil {
			t.Errorf("validateVanity() failed, vanity validation succeded for invalid domain: %s", v)
		}
	}
}
