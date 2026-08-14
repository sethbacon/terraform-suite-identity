// Package notests holds only a test file, so a scan pointed here has no
// non-test source to look at. A guard that reported "no findings" for it would
// be certifying a package it never read.
package notests

import "testing"

func TestNothing(t *testing.T) {}
