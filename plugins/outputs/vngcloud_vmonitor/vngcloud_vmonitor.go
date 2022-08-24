package vngcloud_vmonitor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"

	"github.com/denisbrodbeck/machineid"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/plugins/inputs/system"
	"github.com/shirou/gopsutil/cpu"

	//"github.com/zcalusic/sysinfo"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/internal"
	"github.com/influxdata/telegraf/plugins/outputs"
	"github.com/influxdata/telegraf/plugins/serializers"

	"github.com/matishsiao/goInfo"
)

const (
	defaultURL = "https://monitoring-agent.vngcloud.vn"
	oauthPath  = "/metric-api/v1/metric-agent/token"
	metricPath = "/intake/v1/series"
	//refreshPath = "refresh-token"
)

var sampleConfig = `
  ## URL is the address to send metrics to
  url = "https://monitoring-agent.vngcloud.vn"
  insecure_skip_verify = false
  data_format = "vngcloud_vmonitor"
  api_key = "tBvNQhz49V9Zn5uRaryMBkOdtMVjWAGy"

  # proxy_url = "http://127.0.0.1:8008"
  # timeout = "5s"
`

const (
	defaultClientTimeout = 5 * time.Second
	defaultContentType   = "application/json"
	defaultMethod        = http.MethodPost
	apiKey               = "X-API-Key"
	InsecureSkipVerify   = false
	AgentVersion         = "1.23.0-1.1.0"
)

type Oauth2Access struct {
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type Auth struct {
	ApiKey string `toml:"api_key"`
}

type AuthToken struct {
	Checksum string    `json:"checksum"`
	Data     *infoHost `json:"data"`
}

type AuthRefreshToken struct {
	Checksum     string    `json:"checksum"`
	Data         *infoHost `json:"data"`
	RefreshToken string    `json:"refresh_token"`
}

type Request struct {
	Method string
	Path   string
	Body   []byte
}

type Plugin struct {
	Name    string `json:"name"`
	Status  int    `json:"status"`
	Message string `json:"message"`
}

type infoHost struct {
	Plugins []*Plugin `json:"plugins"`

	HashID string `json:"hash_id"`

	Kernel       string `json:"kernel"`
	Core         string `json:"core"`
	Platform     string `json:"platform"`
	OS           string `json:"os"`
	Hostname     string `json:"host_name"`
	CPUs         int    `json:"cpus"`
	ModelNameCPU string `json:"model_name_cpu"`
	Mem          uint64 `json:"mem"`
	Ip           string `json:"ip"`
	MacAddress   string `json:"mac_address"`
	AgentVersion string `json:"agent_version"`
}

type VNGCloudvMonitor struct {
	URL             string            `toml:"url"`
	Timeout         config.Duration   `toml:"timeout"`
	Method          string            `toml:"method"`
	Headers         map[string]string `toml:"headers"`
	ContentEncoding string            `toml:"content_encoding"`
	ApiKey          string            `toml:"api_key"`
	Insecure        bool              `toml:"insecure_skip_verify"`
	ProxyStr        string            `toml:"proxy_url"`

	Requests   *Request
	client     *http.Client
	serializer serializers.Serializer
	Oauth      *Oauth2Access
	infoHost   *infoHost
}

func (h *VNGCloudvMonitor) SetSerializer(serializer serializers.Serializer) {
	h.serializer = serializer
}

func (h *VNGCloudvMonitor) makeRequest() ([]byte, error) {
	data := bytes.NewBuffer(h.Requests.Body)
	req, err := http.NewRequest(h.Requests.Method, fmt.Sprintf("%s%s", h.URL, h.Requests.Path), data)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	req.Header.Set(apiKey, h.ApiKey)
	req.Header.Set("Content-Type", defaultContentType)
	req.Header.Set("Hash-ID", h.infoHost.HashID)
	userAgent := fmt.Sprintf("%s/%s (%s)", "vMonitorAgent", AgentVersion, h.infoHost.OS)
	req.Header.Set("User-Agent", userAgent)

	res, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}

	log.Printf("[vMonitor] Request-ID: %s with body length %d byte", res.Header.Get("Api-Request-ID"), len(h.Requests.Body))

	if res.StatusCode < 200 || res.StatusCode > 209 {
		data, _ := ioutil.ReadAll(res.Body)
		//log.Printf("[vMonitor] Response body: %s with status code: %d", string(data), res.StatusCode)
		return nil, fmt.Errorf("HTTP request failed: %s status_code: %d", string(data), res.StatusCode)
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func getMacAddressFromIP(ipLocal string) (string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		ipTemp, _ := ifa.Addrs()
		for _, v := range ipTemp {
			ip, _, _ := net.ParseCIDR(v.String())
			if ip.String() == ipLocal {
				return a, nil
			}
		}
	}
	return "", nil
}

func getIp(address, port string) (string, error) {
	log.Printf("Dial %s %s", address, port)
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(address, port), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return strings.Split(conn.LocalAddr().String(), ":")[0], nil
}

func getModelNameCPU() (string, error) {
	a, err := cpu.Info()
	if err != nil {
		return "", err
	}
	return a[0].ModelName, nil
}

func (h *VNGCloudvMonitor) getHostInfo() (*infoHost, error) {

	hashedID, err := machineid.ProtectedID("baea4abca89b98fa6f557ff658135a346b661adb6cc5fa39c86d4fbc4f6ae503")
	if err != nil {
		return nil, err
	}

	getHostPort := func(urlStr string) (string, error) {
		u, err := url.Parse(urlStr)
		if err != nil {
			return "", fmt.Errorf("proxy invalid %s", h.ProxyStr)
		}

		host, port, err := net.SplitHostPort(u.Host)

		if err != nil {
			return "", err
		}

		ipLocal, err := getIp(host, port)
		if err != nil {
			return "", err
		}
		return ipLocal, nil
	}

	var ipLocal string
	// get ip local
	if h.ProxyStr != "" {
		ipLocal, err = getHostPort(h.ProxyStr)
	} else {
		ipLocal, err = getHostPort(h.URL)
	}

	if err != nil {
		return nil, fmt.Errorf("err getting ip address %s", err.Error())
	}
	macAddress, err := getMacAddressFromIP(ipLocal)
	if err != nil {
		return nil, fmt.Errorf("err getting mac_address %s", err.Error())
	}
	// get ip local

	gi, err := goInfo.GetInfo()
	if err != nil {
		return nil, fmt.Errorf("error getting os info: %s", err)
	}
	ps := system.NewSystemPS()
	vm, err := ps.VMStat()

	hashCode := sha256.New()
	hashCode.Write([]byte(fmt.Sprintf("%s%s%s", hashedID, macAddress, gi.Hostname)))
	hashedID = hex.EncodeToString(hashCode.Sum(nil))

	if err != nil {
		return nil, fmt.Errorf("error getting virtual memory info: %s", err)
	}

	modelNameCPU, err := getModelNameCPU()

	if err != nil {
		return nil, fmt.Errorf("error getting cpu model name: %s", err)
	}

	h.infoHost.HashID = hashedID
	h.infoHost.Kernel = gi.Kernel
	h.infoHost.Core = gi.Core
	h.infoHost.Platform = gi.Platform
	h.infoHost.OS = gi.OS
	h.infoHost.CPUs = gi.CPUs
	h.infoHost.ModelNameCPU = modelNameCPU
	h.infoHost.Mem = vm.Total
	h.infoHost.Ip = ipLocal
	h.infoHost.MacAddress = macAddress
	h.infoHost.AgentVersion = AgentVersion

	return h.infoHost, nil
}

func (h *VNGCloudvMonitor) getAccessKey() error {
	log.Print("[vMonitor] Get access token from api key: <API_KEY>")
	jsonData, _ := json.Marshal(h.infoHost)
	log.Printf("[vMonitor] Info: %s", jsonData)

	authStruct := &AuthToken{
		Checksum: h.infoHost.HashID,
		Data:     h.infoHost,
	}

	dataAuth, err := json.Marshal(authStruct)

	if err != nil {
		panic(err.Error())
	}

	h.Requests = &Request{
		Method: http.MethodPost,
		Path:   oauthPath,
		Body:   dataAuth,
	}

	resBody, err := h.makeRequest()
	if err != nil {
		return err
	}
	err = json.Unmarshal(resBody, &h.Oauth)

	if err != nil {
		log.Printf("[vMonitor] Cannot decode json when get access key from api key: %s", err.Error())
		log.Printf("[vMonitor] Data: < %s >", resBody)
		return err
	}

	log.Print("[vMonitor] Get access token successfully!")
	return nil
}

func (h *VNGCloudvMonitor) getAccessTokenFromRefreshToken() error {
	log.Print("[vMonitor] Get access token from refresh token")
	jsonData, _ := json.Marshal(h.infoHost)
	log.Printf("[vMonitor] Info: %s", jsonData)

	authStruct := &AuthRefreshToken{
		Checksum:     h.infoHost.HashID,
		Data:         h.infoHost,
		RefreshToken: h.Oauth.RefreshToken,
	}

	dataAuth, err := json.Marshal(authStruct)

	if err != nil {
		return err
	}

	h.Requests = &Request{
		Method: http.MethodPut,
		Path:   oauthPath,
		Body:   dataAuth,
	}

	data, err := h.makeRequest()
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &h.Oauth)

	if err != nil {
		log.Print(err.Error())
		return err
	}
	log.Print("[vMonitor] Get refresh token successfully!")
	return nil
}

func (h *VNGCloudvMonitor) createClient(ctx context.Context) (*http.Client, error) {
	//adding the proxy settings to the Transport object
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: h.Insecure},
	}

	if h.ProxyStr != "" {
		proxyURL, err := url.Parse(h.ProxyStr)
		if err != nil {
			log.Println(err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(h.Timeout),
	}

	return client, nil
}

func (h *VNGCloudvMonitor) setDefault() error {
	if h.Method == "" {
		h.Method = http.MethodPost
	}

	h.Method = strings.ToUpper(h.Method)
	if h.Method != http.MethodPost && h.Method != http.MethodPut {
		return fmt.Errorf("[vMonitor] Invalid method [%s] %s", h.URL, h.Method)
	}

	if h.Timeout == 0 {
		h.Timeout = config.Duration(defaultClientTimeout)
	}
	return nil
}

func isUrl(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func (h *VNGCloudvMonitor) CheckConfig() error {
	ok := isUrl(h.URL)
	if !ok {
		// log.Printf("URL Invalid %s", h.URL)
		return fmt.Errorf("URL Invalid %s", h.URL)
	}
	return nil
}

func (h *VNGCloudvMonitor) Connect() error {

	if err := h.CheckConfig(); err != nil {
		return err
	}

	if err := h.setDefault(); err != nil {
		return err
	}

	ctx := context.Background()
	client, err := h.createClient(ctx)
	if err != nil {
		return err
	}

	h.client = client

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
	//log.Print(sampleConfig)
	return sampleConfig
}

func (h *VNGCloudvMonitor) setPlugins(metrics []telegraf.Metric) error {
	a := h.infoHost.Plugins
	nameTemp := ""
	hostname := ""

	existCheck := func(name string) bool {
		for _, e := range a {
			if name == e.Name {
				return true
			}
		}
		return false
	}
	for _, element := range metrics {
		if element.Name() != nameTemp || nameTemp == "" {
			if !existCheck(element.Name()) {
				hostTemp, ok := element.GetTag("host")

				if ok {
					hostname = hostTemp
				}

				msg := "running"
				a = append(a, &Plugin{
					Name:    element.Name(),
					Status:  0,
					Message: msg,
				})
				nameTemp = element.Name()
			}
		}
	}

	if hostname == "" && h.infoHost.Hostname == "" {
		hostnameTemp, err := os.Hostname()
		if err != nil {
			return err
		}
		h.infoHost.Hostname = hostnameTemp
	}
	if hostname != "" {
		h.infoHost.Hostname = hostname
	}
	h.infoHost.Plugins = a
	return nil
}

func (h *VNGCloudvMonitor) Write(metrics []telegraf.Metric) error {

	if err := h.setPlugins(metrics); err != nil {
		return err
	}

	if h.Oauth == nil {
		log.Print("Start Authorization")
		if err := h.authorization(); err != nil {
			return err
		}
	}

	reqBody, err := h.serializer.SerializeBatch(metrics)
	if err != nil {
		return err
	}

	if err := h.write(reqBody); err != nil {
		return err
	}

	return nil
}

func (h *VNGCloudvMonitor) authorization() error {
	err := h.getAccessKey()
	if err != nil {
		// log.Printf("[vMonitor] Fail Authorization: %s", err.Error())
		return err
	}
	return nil
}

func (h *VNGCloudvMonitor) write(reqBody []byte) error {
	var reqBodyBuffer io.Reader = bytes.NewBuffer(reqBody)

	var err error
	if h.ContentEncoding == "gzip" {
		rc, err := internal.CompressWithGzip(reqBodyBuffer)
		if err != nil {
			return err
		}
		defer rc.Close()
		reqBodyBuffer = rc
	}

	req, err := http.NewRequest(h.Method, fmt.Sprintf("%s%s", h.URL, metricPath), reqBodyBuffer)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", defaultContentType)
	req.Header.Set("Hash-ID", h.infoHost.HashID)
	userAgent := fmt.Sprintf("%s/%s (%s)", "vMonitorAgent", AgentVersion, h.infoHost.OS)
	req.Header.Set("User-Agent", userAgent)

	if h.ContentEncoding == "gzip" {
		req.Header.Set("Content-Encoding", "gzip")
	}
	for k, v := range h.Headers {
		if strings.ToLower(k) == "host" {
			req.Host = v
		}
		req.Header.Set(k, v)
	}

	req.Header.Set("Authorization", fmt.Sprintf("%s %s", h.Oauth.TokenType, h.Oauth.AccessToken))
	resp, err := h.client.Do(req)

	if err != nil {
		return err
	}
	defer resp.Body.Close()
	dataRsp, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	log.Printf("[vMonitor] Request-ID: %s with body length %d byte and response body %s", resp.Header.Get("Api-Request-ID"), len(reqBody), dataRsp)

	if resp.StatusCode == 401 {
		err = h.getAccessTokenFromRefreshToken()
		if err != nil {
			if err = h.authorization(); err != nil {
				return err
			}
		}
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// return fmt.Errorf("received bad status code, %d", resp.StatusCode)
		return fmt.Errorf("when writing to [%s] received status code: %d", h.URL, resp.StatusCode)
	}

	if err != nil {
		return fmt.Errorf("when writing to [%s] received error: %v", h.URL, err)
	}

	return nil
}

func init() {
	outputs.Add("vngcloud_vmonitor", func() telegraf.Output {
		infoHosts := &infoHost{
			Plugins:  []*Plugin{},
			HashID:   "",
			Kernel:   "",
			Core:     "",
			Platform: "",
			OS:       "",
			Hostname: "",
			CPUs:     0,
			Mem:      0,
		}
		log.Print("#################### Welcome to vMonitor (VNGCLOUD) ####################")
		return &VNGCloudvMonitor{
			Timeout:  config.Duration(defaultClientTimeout),
			Method:   defaultMethod,
			URL:      defaultURL,
			infoHost: infoHosts,
		}
	})
}
