//go:build !custom || inputs || inputs.xfs

package all

import _ "github.com/influxdata/telegraf/plugins/inputs/xfs" // register plugin
