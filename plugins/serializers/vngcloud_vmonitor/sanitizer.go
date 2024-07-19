package vngcloud_vmonitor

import (
	"strings"
	"unicode"
)

type Table struct {
	First           *unicode.RangeTable
	Rest            *unicode.RangeTable
	BlackListValues *unicode.RangeTable
}

const (
	MaxCharDmsValue   = 255
	MinCharDmsValue   = 1
	MaxCharMetricName = 255
	MinCharMetricName = 1
)

var MetricNameTable = Table{
	First: &unicode.RangeTable{
		R16: []unicode.Range16{
			// {0x003A, 0x003A, 1}, // :
			{0x0041, 0x005A, 1}, // A-Z
			{0x005F, 0x005F, 1}, // _
			{0x0061, 0x007A, 1}, // a-z
		},
		LatinOffset: 3,
	},
	Rest: &unicode.RangeTable{
		R16: []unicode.Range16{
			{0x002D, 0x0039, 1}, // - . / and 0-9
			{0x0041, 0x005A, 1}, // A-Z
			{0x005F, 0x005F, 1}, // _
			{0x0061, 0x007A, 1}, // a-z
		},
		LatinOffset: 4,
	},
}

var DimensionNameTable = Table{
	First: &unicode.RangeTable{
		R16: []unicode.Range16{
			{0x0041, 0x005A, 1}, // A-Z
			{0x005F, 0x005F, 1}, // _
			{0x0061, 0x007A, 1}, // a-z
		},
		LatinOffset: 3,
	},
	Rest: &unicode.RangeTable{
		R16: []unicode.Range16{
			{0x002D, 0x0039, 1}, // - . / and 0-9
			{0x0041, 0x005A, 1}, // A-Z
			{0x005F, 0x005F, 1}, // _
			{0x0061, 0x007A, 1}, // a-z
		},
		LatinOffset: 4,
	},
}

var DimensionValueTable = Table{
	First: &unicode.RangeTable{
		R16: []unicode.Range16{
			{0x002D, 0x0039, 1}, // - . / and 0-9
			{0x0041, 0x005A, 1}, // A-Z
			{0x005F, 0x005F, 1}, // _
			{0x0061, 0x007A, 1}, // a-z
		},
		LatinOffset: 4,
	},
	Rest: &unicode.RangeTable{
		R16: []unicode.Range16{
			{0x002D, 0x0039, 1}, // - . / and 0-9
			{0x0041, 0x005A, 1}, // A-Z
			{0x005F, 0x005F, 1}, // _
			{0x0061, 0x007A, 1}, // a-z
		},
		LatinOffset: 4,
	},
	BlackListValues: &unicode.RangeTable{
		R16: []unicode.Range16{
			{0x0022, 0x0022, 1}, // "
			{0x0026, 0x0026, 1}, // &
			{0x003B, 0x003B, 1}, // ;
			{0x003C, 0x003E, 1}, // < = >
			{0x005C, 0x005C, 1}, // \
			{0x007B, 0x007D, 1}, // { | }
		},
		LatinOffset: 6,
	},
}

func sanitizeWhiteList(name string, table Table) (string, bool) {
	var b strings.Builder
	for i, r := range name {
		switch {
		case i == 0:
			if unicode.In(r, table.First) {
				b.WriteRune(r)
			}
		default:
			if unicode.In(r, table.Rest) {
				b.WriteRune(r)
			} else {
				b.WriteString("_")
			}
		}
	}
	name = strings.Trim(b.String(), "_")
	if name == "" {
		return "", false
	}

	return name, true
}

func sanitizeBlackList(name string, table Table) (string, bool) {
	var b strings.Builder
	for _, r := range name {
		if unicode.In(r, table.BlackListValues) {
			b.WriteString("_")
		} else {
			b.WriteRune(r)
		}
	}
	name = strings.Trim(b.String(), "_")
	if name == "" {
		return "", false
	}

	return name, true
}

// SanitizeMetricName checks if the name is a valid Prometheus metric name.  If
// not, it attempts to replaces invalid runes with an underscore to create a
// valid name.
func SanitizeMetricName(name string) (string, bool) {
	return sanitizeWhiteList(name, MetricNameTable)
}

// SanitizeDimensionName checks if the name is a valid Prometheus label name.  If
// not, it attempts to replaces invalid runes with an underscore to create a
// valid name.
func SanitizeDimensionName(name string) (string, bool) {
	return sanitizeWhiteList(name, DimensionNameTable)
}

func SanitizeDimensionValue(name string) (string, bool) {
	// return sanitizeBlackList(name, DimensionValueTable)
	return sanitizeWhiteList(name, DimensionValueTable)
}
