package vngcloud_vmonitor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/internal"
	"github.com/influxdata/telegraf/plugins/common/proxy"
	"github.com/influxdata/telegraf/plugins/inputs/system"
	"github.com/influxdata/telegraf/plugins/outputs"
	"github.com/influxdata/telegraf/plugins/serializers"
	"github.com/matishsiao/goInfo"
	"github.com/shirou/gopsutil/cpu"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	metricPath         = "/intake/v2/series"
	quotaPath          = "/intake/v2/check"
	defaultContentType = "application/json"
	agentVersion       = "1.26.0-2.0.0"
	retryTime          = 128 // = 2^7 => retry max 128*30s
)

var defaultConfig = &VNGCloudvMonitor{
	URL:             "http://localhost:8081",
	Timeout:         config.Duration(10 * time.Second),
	IamURL:          "https://hcm-3.console.vngcloud.vn/iam/accounts-api/v2/auth/token",
	checkQuotaRetry: config.Duration(30 * time.Second),
}

var sampleConfig = `
  ## URL is the address to send metrics to
  url = "http://localhost:8081"
  insecure_skip_verify = false
  data_format = "vngcloud_vmonitor"
  timeout = "30s"

  # From IAM service
  client_id = ""
  client_secret = ""
`

type Plugin struct {
	Name    string `json:"name"`
	Status  int    `json:"status"`
	Message string `json:"message"`
}

type QuotaInfo struct {
	Checksum string    `json:"checksum"`
	Data     *infoHost `json:"data"`
}

type infoHost struct {
	Plugins     []Plugin        `json:"plugins"`
	PluginsList map[string]bool `json:"-"`

	HashID string `json:"hash_id"`

	Kernel       string `json:"kernel"`
	Core         string `json:"core"`
	Platform     string `json:"platform"`
	OS           string `json:"os"`
	Hostname     string `json:"host_name"`
	CPUs         int    `json:"cpus"`
	ModelNameCPU string `json:"model_name_cpu"`
	Mem          uint64 `json:"mem"`
	IP           string `json:"ip"`
	AgentVersion string `json:"agent_version"`
	UserAgent    string `toml:"user_agent"`
}

type VNGCloudvMonitor struct {
	URL             string          `toml:"url"`
	Timeout         config.Duration `toml:"timeout"`
	ContentEncoding string          `toml:"content_encoding"`
	Insecure        bool            `toml:"insecure_skip_verify"`
	proxy.HTTPProxy
	Log telegraf.Logger `toml:"-"`

	IamURL       string `toml:"iam_url"`
	ClientID     string `toml:"client_id"`
	ClientSecret string `toml:"client_secret"`

	serializer serializers.Serializer
	infoHost   *infoHost
	clientIam  *http.Client

	checkQuotaRetry config.Duration
	dropCount       int
	dropTime        time.Time
	checkQuotaFirst bool
}

func (h *VNGCloudvMonitor) SetSerializer(serializer serializers.Serializer) {
	h.serializer = serializer
}

func (h *VNGCloudvMonitor) initHTTPClient() error {
	h.Log.Debug("Target: ", "monitoring-agent.vngcloud.vn ", getIPTarget("monitoring-agent.vngcloud.vn"))
	h.Log.Debug("Target: ", "iamapis.vngcloud.vn ", getIPTarget("iamapis.vngcloud.vn"))
	h.Log.Debug("Init client-iam ...")
	oauth2ClientConfig := &clientcredentials.Config{
		ClientID:     h.ClientID,
		ClientSecret: h.ClientSecret,
		TokenURL:     h.IamURL,
	}
	proxyFunc, err := h.Proxy()
	if err != nil {
		return err
	}
	ctx := context.WithValue(context.TODO(), oauth2.HTTPClient, &http.Client{
		Transport: &http.Transport{
			Proxy: proxyFunc,
		},
		Timeout: time.Duration(h.Timeout),
	})
	token, err := oauth2ClientConfig.TokenSource(ctx).Token()
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	_, err = json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to Marshal token: %w", err)
	}
	h.clientIam = oauth2ClientConfig.Client(ctx)
	h.Log.Info("Init client-iam successfully !")
	return nil
}

func getIPTarget(target string) string {
	ips, _ := net.LookupIP(target)
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String()
		}
	}
	return ""
}

// GetLocalIP returns the non loopback local IP of the host
func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func getModelNameCPU() (string, error) {
	a, err := cpu.Info()
	if err != nil {
		return "", err
	}
	return a[0].ModelName, nil
}

func (h *VNGCloudvMonitor) getHostInfo() (*infoHost, error) {
	ipLocal := GetLocalIP()
	var err error

	gi, err := goInfo.GetInfo()
	if err != nil {
		return nil, fmt.Errorf("error getting os info: %w", err)
	}
	ps := system.NewSystemPS()
	vm, err := ps.VMStat()

	if err != nil {
		return nil, fmt.Errorf("error getting virtual memory info: %w", err)
	}

	modelNameCPU, err := getModelNameCPU()

	if err != nil {
		return nil, fmt.Errorf("error getting cpu model name: %w", err)
	}

	h.infoHost = &infoHost{
		Plugins:      []Plugin{},
		PluginsList:  make(map[string]bool),
		Hostname:     "",
		HashID:       "",
		Kernel:       gi.Kernel,
		Core:         gi.Core,
		Platform:     gi.Platform,
		OS:           gi.OS,
		CPUs:         gi.CPUs,
		ModelNameCPU: modelNameCPU,
		Mem:          vm.Total,
		IP:           ipLocal,
		AgentVersion: agentVersion,
		UserAgent:    fmt.Sprintf("%s/%s (%s)", "vMonitorAgent", agentVersion, gi.OS),
	}
	h.setHostname(gi.Hostname)
	return h.infoHost, nil
}

func isURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func (h *VNGCloudvMonitor) CheckConfig() error {
	ok := isURL(h.URL)
	if !ok {
		return fmt.Errorf("URL Invalid %s", h.URL)
	}
	return nil
}

func (h *VNGCloudvMonitor) Connect() error {
	if err := h.CheckConfig(); err != nil {
		return err
	}

	// h.client_iam = client_iam
	err := h.initHTTPClient()
	if err != nil {
		h.Log.Info(err)
		return err
	}

	_, err = h.getHostInfo()
	if err != nil {
		return err
	}

	return nil
}

func (h *VNGCloudvMonitor) Close() error {
	return nil
}

func (h *VNGCloudvMonitor) Description() string {
	return "Configuration for vMonitor output."
}

func (h *VNGCloudvMonitor) SampleConfig() string {
	return sampleConfig
}

func (h *VNGCloudvMonitor) setHostname(hostname string) {
	hashCode := sha256.New()
	hashCode.Write([]byte(hostname))
	hashedID := hex.EncodeToString(hashCode.Sum(nil))

	h.infoHost.HashID = hashedID
	h.infoHost.Hostname = hostname
}

func (h *VNGCloudvMonitor) setPlugins(metrics []telegraf.Metric) error {
	hostname := ""
	for _, metric := range metrics {
		if _, exists := h.infoHost.PluginsList[metric.Name()]; !exists {
			hostTemp, ok := metric.GetTag("host")

			if ok {
				hostname = hostTemp
			}

			msg := "running"
			h.infoHost.Plugins = append(h.infoHost.Plugins, Plugin{
				Name:    metric.Name(),
				Status:  0,
				Message: msg,
			})
			h.infoHost.PluginsList[metric.Name()] = true
		}
	}
	if hostname != "" {
		h.setHostname(hostname)
	} else if h.infoHost.Hostname == "" {
		hostnameTemp, err := os.Hostname()
		if err != nil {
			return err
		}
		h.setHostname(hostnameTemp)
	}
	return nil
}

func (h *VNGCloudvMonitor) Write(metrics []telegraf.Metric) error {
	if h.dropCount > 1 && time.Now().Before(h.dropTime) {
		h.Log.Warnf("Drop %d metrics. Send request again at %s", len(metrics), h.dropTime.Format("15:04:05"))
		return nil
	}

	if err := h.setPlugins(metrics); err != nil {
		return err
	}

	if h.checkQuotaFirst {
		if isDrop, err := h.checkQuota(); err != nil {
			if isDrop {
				h.Log.Warnf("Drop metrics because of %w", err)
				return nil
			}
			return err
		}
	}

	reqBody, err := h.serializer.SerializeBatch(metrics)
	if err != nil {
		return err
	}

	var reqBodyBuffer io.Reader = bytes.NewBuffer(reqBody)

	if h.ContentEncoding == "gzip" {
		rc := internal.CompressWithGzip(reqBodyBuffer)
		defer rc.Close()
		reqBodyBuffer = rc
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s%s", h.URL, metricPath), reqBodyBuffer)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", defaultContentType)
	req.Header.Set("checksum", h.infoHost.HashID)
	req.Header.Set("User-Agent", h.infoHost.UserAgent)

	if h.ContentEncoding == "gzip" {
		req.Header.Set("Content-Encoding", "gzip")
	}

	resp, err := h.clientIam.Do(req)
	if err != nil {
		if er := h.initHTTPClient(); er != nil {
			h.Log.Warnf("Drop metrics because can't init IAM: %s", er.Error())
			return nil
		}
		return fmt.Errorf("IAM request fail: %w", err)
	}
	defer resp.Body.Close()
	dataRsp, err := io.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	h.Log.Infof("Request-ID: %s with body length %d byte and response body %s", resp.Header.Get("Api-Request-ID"), len(reqBody), dataRsp)

	if isDrop, err := h.handleResponse(resp.StatusCode, dataRsp); err != nil {
		if isDrop {
			h.Log.Warnf("Drop metrics because of %w", err)
			return nil
		}
		return err
	}
	return nil
}

func (h *VNGCloudvMonitor) handleResponse(respCode int, dataRsp []byte) (bool, error) {
	switch respCode {
	case 201:
		return false, nil
	case 401:
		return true, fmt.Errorf("IAM Unauthorized. Please check your service account")
	case 403:
		return true, fmt.Errorf("IAM Forbidden. Please check your permission")
	case 428:
		if isDrop, err := h.checkQuota(); err != nil {
			return isDrop, fmt.Errorf("can not check quota: %w", err)
		}
	case 409:
		h.doubleCheckTime()
		return true, fmt.Errorf("CONFLICT. Please check your quota again")
	}
	return false, fmt.Errorf("status Code: %d, message: %s", respCode, dataRsp)
}

func (h *VNGCloudvMonitor) checkQuota() (bool, error) {
	h.Log.Info("Start check quota ...")
	h.checkQuotaFirst = true

	quotaStruct := &QuotaInfo{
		Checksum: h.infoHost.HashID,
		Data:     h.infoHost,
	}
	quotaJSON, err := json.Marshal(quotaStruct)
	if err != nil {
		return false, fmt.Errorf("can not marshal quota struct: %w", err)
	}

	h.Log.Debugf("Request check quota body: %s", string(quotaJSON))

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s%s", h.URL, quotaPath), bytes.NewBuffer(quotaJSON))
	if err != nil {
		return false, fmt.Errorf("error create new request: %w", err)
	}
	req.Header.Set("checksum", h.infoHost.HashID)
	req.Header.Set("Content-Type", defaultContentType)
	req.Header.Set("User-Agent", h.infoHost.UserAgent)
	resp, err := h.clientIam.Do(req)

	if err != nil {
		return false, fmt.Errorf("send request checking quota failed: (%w)", err)
	}
	defer resp.Body.Close()
	dataRsp, err := io.ReadAll(resp.Body)

	if err != nil {
		return false, fmt.Errorf("error occurred when reading response body: (%w)", err)
	}

	isDrop := false
	// handle check quota
	switch resp.StatusCode {
	case 200:
		h.Log.Infof("Request-ID: %s. Checking quota success. Continue send metric.", resp.Header.Get("Api-Request-ID"))
		h.dropCount = 1
		h.dropTime = time.Now()
		h.checkQuotaFirst = false
		return false, nil

	case 401, 403:
		isDrop = true
	case 409:
		isDrop = true
		h.doubleCheckTime()
	}
	return isDrop, fmt.Errorf("Request-ID: %s. Checking quota fail (%d - %s)", resp.Header.Get("Api-Request-ID"), resp.StatusCode, dataRsp)
}

func init() {
	outputs.Add("vngcloud_vmonitor", func() telegraf.Output {
		infoHosts := &infoHost{
			// Plugins: map[string]*Plugin{
			// 	"haha": nil,
			// },
			Plugins:     []Plugin{},
			PluginsList: make(map[string]bool),
			HashID:      "",
			Kernel:      "",
			Core:        "",
			Platform:    "",
			OS:          "",
			Hostname:    "",
			CPUs:        0,
			Mem:         0,
		}
		return &VNGCloudvMonitor{
			Timeout:         defaultConfig.Timeout,
			URL:             defaultConfig.URL,
			IamURL:          defaultConfig.IamURL,
			checkQuotaRetry: defaultConfig.checkQuotaRetry,
			infoHost:        infoHosts,

			dropCount:       1,
			dropTime:        time.Now(),
			checkQuotaFirst: false,
		}
	})
}

func (h *VNGCloudvMonitor) doubleCheckTime() {
	if h.dropCount < retryTime {
		h.dropCount = h.dropCount * 2
	}
	h.dropTime = time.Now().Add(time.Duration(h.dropCount * int(time.Duration(h.checkQuotaRetry))))
}
