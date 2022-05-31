package vngcloud_vmonitor

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/metric"
)

type MetricMessage struct {
	Metric struct {
		Name       string            `json:"name"`
		Dimensions map[string]string `json:"dimensions"`
		Value      int               `json:"value"`
		Timestamp  int64             `json:"timestamp"`
		ValueMeta  map[string]interface {
		} `json:"value_meta"`
	} `json:"metric"`
	Meta struct {
		Tenantid string `json:"tenantId"`
		Region   string `json:"region"`
	} `json:"meta"`
	CreationTime int64 `json:"creation_time"`
}

type ValueParser struct {
	MetricName  string
	DataType    string
	DefaultTags map[string]string
}

func (v *ValueParser) Parse(buf []byte) ([]telegraf.Metric, error) {
	var data MetricMessage
	err := json.Unmarshal(buf, &data)
	if err != nil {
		return nil, err
	}

	tags := data.Metric.Dimensions
	tags["tenant_id"] = data.Meta.Tenantid
	value := data.Metric.Value
	s := strings.Split(data.Metric.Name, ".")
	fields := map[string]interface{}{strings.Join(s[1:], "."): value}

	timestamp := time.Unix(0, data.Metric.Timestamp*int64(1000000))
	metric := metric.New(s[0], tags, fields, timestamp)

	return []telegraf.Metric{metric}, nil
}

func (v *ValueParser) ParseLine(line string) (telegraf.Metric, error) {
	metrics, err := v.Parse([]byte(line))

	if err != nil {
		return nil, err
	}

	if len(metrics) < 1 {
		return nil, fmt.Errorf("Can not parse the line: %s, for data format: value", line)
	}

	return metrics[0], nil
}

func (v *ValueParser) SetDefaultTags(tags map[string]string) {
	v.DefaultTags = tags
}
