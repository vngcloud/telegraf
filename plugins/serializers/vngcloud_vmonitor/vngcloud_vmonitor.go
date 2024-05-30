package vngcloud_vmonitor

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/influxdata/telegraf"
)

type serializer struct {
	TimestampUnits time.Duration
}

func NewSerializer(timestampUnits time.Duration) (*serializer, error) {
	s := &serializer{
		TimestampUnits: truncateDuration(timestampUnits),
	}
	return s, nil
}

func (s *serializer) Serialize(metric telegraf.Metric) ([]byte, error) {
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

func (s *serializer) SerializeBatch(metrics []telegraf.Metric) ([]byte, error) {
	var objects []interface{}

	for _, metric := range metrics {
		m, err := s.createObject(metric)
		if err != nil {
			log.Println(err)
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
	log.Printf("[serials.vngcloud_vmonitor] Serialized batch %d metrics to %d objects", len(metrics), len(objects))
	return serialized, nil
}

// func (s *serializer) isNumeric(str string) bool {
// 	_, err := strconv.ParseFloat(str, 64)
// 	return err == nil
// }

func (s *serializer) convertValueToFloat(v interface{}, name string) (float64, bool) {
	invalidLog := func() {
		log.Printf("[serials.vngcloud_vmonitor] Metric_value invalid with value: %s -> %v(%T)", name, v, v)
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

func (s *serializer) createObject(metric telegraf.Metric) ([]map[string]interface{}, error) {
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

func truncateDuration(units time.Duration) time.Duration {
	// Default precision is 1s
	if units <= 0 {
		return time.Second
	}

	// Search for the power of ten less than the duration
	d := time.Nanosecond
	for {
		if d*10 > units {
			return d
		}
		d = d * 10
	}
}
