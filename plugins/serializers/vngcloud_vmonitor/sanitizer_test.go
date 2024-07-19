package vngcloud_vmonitor

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type SanitizeTest struct {
	name   string
	result string
	valid  bool
}

func Test_SanitizeMetricName(t *testing.T) {
	tests := []SanitizeTest{
		{"cpu", "cpu", true},
		{"cpu*", "cpu", true},
		{"cpu%", "cpu", true},
		{"cpu&", "cpu", true},
		{"cpu(", "cpu", true},
		{"cpu)", "cpu", true},
		{"cpu=", "cpu", true},
		{"cpu+", "cpu", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, _ := SanitizeMetricName(tt.name)
			require.Equal(t, tt.result, name)
		})
	}
}

func Test_SanitizeDimensionName(t *testing.T) {
	tests := []SanitizeTest{
		{"usage", "usage", true},
		{"usage*", "usage", true},
		{"usage%", "usage", true},
		{"usage&", "usage", true},
		{"usage(", "usage", true},
		{"usage)", "usage", true},
		{"usage=", "usage", true},
		{"usage+", "usage", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, ok := SanitizeDimensionValue(tt.name)
			require.Equal(t, tt.result, name)
			require.Equal(t, tt.valid, ok)
		})
	}
}

func Test_SanitizeDimensionValue(t *testing.T) {
	tests := []SanitizeTest{
		{"value", "value", true},
		{"value*", "value", true},
		{"value%", "value", true},
		{"value&", "value", true},
		{"value(", "value", true},
		{"value)", "value", true},
		{"value=", "value", true},
		{"value+", "value", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, ok := SanitizeDimensionValue(tt.name)
			require.Equal(t, tt.result, name)
			require.Equal(t, tt.valid, ok)
		})
	}
}

func Test_sanitizeBlackList(t *testing.T) {
	tests := []SanitizeTest{
		{"value", "value", true},
		{"value*", "value*", true},
		{"value%", "value%", true},
		{"value&", "value", true},
		{"value(", "value(", true},
		{"value)", "value)", true},
		{"value=", "value", true},
		{"value+", "value+", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, ok := sanitizeBlackList(tt.name, DimensionValueTable)
			require.Equal(t, tt.result, name)
			require.Equal(t, tt.valid, ok)
		})
	}
}
