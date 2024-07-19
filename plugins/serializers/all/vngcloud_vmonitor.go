//go:build !custom || serializers || serializers.vngcloud_vmonitor

package all

import (
	_ "github.com/influxdata/telegraf/plugins/serializers/vngcloud_vmonitor" // register plugin
)
