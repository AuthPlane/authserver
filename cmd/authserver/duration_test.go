package main

import (
	"testing"
	"time"
)

func TestParseDurationExt(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{name: "hours", input: "1h", want: time.Hour},
		{name: "minutes", input: "30m", want: 30 * time.Minute},
		{name: "seconds", input: "90s", want: 90 * time.Second},
		{name: "compound", input: "1h30m", want: 90 * time.Minute},
		{name: "single day", input: "1d", want: 24 * time.Hour},
		{name: "seven days", input: "7d", want: 7 * 24 * time.Hour},
		{name: "thirty days", input: "30d", want: 30 * 24 * time.Hour},
		{name: "single week", input: "1w", want: 7 * 24 * time.Hour},
		{name: "two weeks", input: "2w", want: 14 * 24 * time.Hour},

		{name: "empty rejected", input: "", wantErr: true},
		{name: "fractional days rejected", input: "1.5d", wantErr: true},
		{name: "zero days rejected", input: "0d", wantErr: true},
		{name: "negative days rejected", input: "-1d", wantErr: true},
		{name: "zero weeks rejected", input: "0w", wantErr: true},
		{name: "garbage day prefix", input: "abcd", wantErr: true},
		{name: "garbage week prefix", input: "abcw", wantErr: true},
		{name: "unknown suffix", input: "1y", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDurationExt(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q, got %v", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("parseDurationExt(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
