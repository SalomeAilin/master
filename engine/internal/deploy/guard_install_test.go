package deploy

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGuardOnlyInstallationAndRollback(t *testing.T) {
	for _, fault := range []string{"", "syntax", "publication", "digest"} {
		t.Run(fault, func(t *testing.T) {
			d := maintenanceFixture(t)
			source := filepath.Join(d.Root, routeGuardName)
			target := filepath.Join(filepath.Dir(d.Tool), routeGuardName)
			writeTestFile(t, source, "#!/bin/zsh\nexit 0\n")
			original := d.Run
			d.Run = func(args ...string) (string, error) {
				if args[0] == "/bin/zsh" {
					if !reflect.DeepEqual(args, []string{"/bin/zsh", "-n", source}) {
						t.Fatal("guard execution requested", args)
					}
					if fault == "syntax" {
						return "", errors.New("syntax error")
					}
					return "", nil
				}
				return original(args...)
			}
			failed := false
			d.Rename = func(from, to string) error {
				if to == target && !failed {
					failed = true
					if fault == "publication" {
						return errors.New("publication failed")
					}
					if fault == "digest" {
						writeTestFile(t, from, "unexpected contents")
					}
				}
				return os.Rename(from, to)
			}
			before, err := d.maintenanceState()
			if err != nil {
				t.Fatal(err)
			}
			err = d.InstallRouteGuard()
			if (err == nil) != (fault == "") {
				t.Fatal("unexpected install outcome", err)
			}
			after, checkErr := d.maintenanceState()
			if fault == "" {
				before.Files[target], _ = fileDigest(source)
			}
			if checkErr != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("runtime changed or rollback incomplete", checkErr)
			}
		})
	}
}
