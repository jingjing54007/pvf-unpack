package main

import "testing"
import "encoding/hex"
import "log"
import "bytes"

func Test_pvfDecrypt(t *testing.T) {
	tests := []struct {
		name string
		h    string
		key  string
		want string
	}{
		// TODO: Add test cases.
		{"",
			"2225E83379981F9B79B334E4B93A523FAB92A1CC1C35281670CAD51C56DACE5C9848919C4309E5E94F6C5369EC69B4BE",
			"hEAd",
			"6E6B7069559947593EAA477E136A52A63B35410EECD694E4F2B40C00882A47023B7DDF028A1B0000C8AB810090AB9300",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := hex.DecodeString(tt.h)
			bw, _ := hex.DecodeString(tt.want)
			pvfDecrypt(b, tt.key)
			log.Println(hex.Dump(b))
			if !bytes.Equal(b, bw) {
				t.Errorf("bad\n")
			}
		})
	}
}
