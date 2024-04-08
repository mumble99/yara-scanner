// utils
package main

import (
	"strings"
)

func contains(sa []string, s string) bool {
	for _, a := range sa {
		if strings.HasPrefix(s, a) {
			return true
		}
	}
	return false
}