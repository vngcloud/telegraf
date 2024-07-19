package vngcloud_vmonitor

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/serializers"
)

type Serializer struct {
	Log telegraf.Logger `toml:"-"`
}

func (s *Serializer) Init() error {
	return nil
}

func (s *Serializer) Serialize(metric telegraf.Metric) ([]byte, error) {
	m, err := s.createObject(metric)
	if err != nil {
		return []byte{}, err
	}
	serialized, err := json.Marshal(m)
	if err != nil {
		return []byte{}, err
	}
	serialized = append(serialized, '\n')

	return serialized, nil
}

func (s *Serializer) SerializeBatch(metrics []telegraf.Metric) ([]byte, error) {
	var objects []interface{}

	for _, metric := range metrics {
		m, err := s.createObject(metric)
		if err != nil {
			s.Log.Error(err)
			continue
		}
		for _, v := range m {
			//log.Print(v)
			objects = append(objects, v)
		}
	}

	if len(objects) == 0 {
		return []byte{}, fmt.Errorf("invalid all metrics name")
	}
	serialized, err := json.Marshal(objects)
	// log.Println(string(serialized))

	if err != nil {
		return []byte{}, err
	}
	s.Log.Infof("[serials.vngcloud_vmonitor] Serialized batch %d metrics to %d objects", len(metrics), len(objects))
	return serialized, nil
}

func (s *Serializer) convertValueToFloat(v interface{}, name string) (float64, bool) {
	invalidLog := func() {
		s.Log.Infof("[serials.vngcloud_vmonitor] Metric_value invalid with value: %s -> %v(%T)", name, v, v)
	}

	switch fv := v.(type) {
	case int64:
		return float64(fv), true
	case uint64:
		return float64(fv), true
	case bool:
		if fv {
			return 1.0, true
		}
		return 0.0, true
	case float64:
		return fv, true
	case string:
		metricValue, err := strconv.ParseFloat(fv, 64)
		if err != nil {
			invalidLog()
			return 0, false
		}
		return metricValue, true
	default:
		invalidLog()
		return 0, false
	}
}

func (s *Serializer) createObject(metric telegraf.Metric) ([]map[string]interface{}, error) {
	metricNamePrefix, ok := SanitizeMetricName(metric.Name())
	if !ok {
		return nil, fmt.Errorf("invalid metric name %s", metric.Name())
	}
	tags := make(map[string]string, len(metric.TagList()))

	for _, tag := range metric.TagList() {
		name, ok := SanitizeDimensionName(tag.Key)
		if !ok || tag.Value == "" {
			continue
		}
		// valueTag, ok := SanitizeLabelValue(tag.Value)
		valueTag, ok := SanitizeDimensionValue(tag.Value)
		if !ok {
			continue
		}
		tags[name] = valueTag
	}

	metrics := make([]map[string]interface{}, 0)
	for _, v := range metric.FieldList() {
		valueTag, ok := SanitizeMetricName(v.Key)
		if !ok {
			continue
		}
		metricName := fmt.Sprintf("%s.%s", metricNamePrefix, valueTag)
		metricValue, ok := s.convertValueToFloat(v.Value, metricName)
		if !ok {
			continue
		}

		m := make(map[string]interface{}, 4)
		m["dimensions"] = tags
		m["name"] = metricName
		m["value"] = metricValue
		m["timestamp"] = metric.Time().UnixNano() / int64(time.Millisecond)
		m["value_meta"] = make(map[string]interface{})
		metrics = append(metrics, m)
	}

	return metrics, nil
}

func init() {
	serializers.Add("vngcloud_vmonitor",
		func() serializers.Serializer {
			return &Serializer{}
		},
	)
}
