// Probe only explicitly listed Meta service names. A retry key is evidence only
// after a second, certificate-verified TLS handshake actually accepts ECH.
package main

import (
    "bytes"
    "crypto/ecdh"
    "crypto/rand"
    "crypto/tls"
    "encoding/base64"
    "encoding/binary"
    "encoding/json"
    "errors"
    "fmt"
    "net"
    "os"
    "regexp"
    "time"
)

func u16(b *bytes.Buffer, n int) { _ = binary.Write(b, binary.BigEndian, uint16(n)) }

func probeSeed(publicName string) ([]byte, error) {
    key, err := ecdh.X25519().GenerateKey(rand.Reader)
    if err != nil { return nil, err }
    var contents, config, list bytes.Buffer
    contents.WriteByte(0xf0)
    u16(&contents, 0x0020) // X25519
    pk := key.PublicKey().Bytes()
    u16(&contents, len(pk)); contents.Write(pk)
    u16(&contents, 4); u16(&contents, 1); u16(&contents, 1)
    contents.WriteByte(0)
    contents.WriteByte(byte(len(publicName))); contents.WriteString(publicName)
    u16(&contents, 0)
    u16(&config, 0xfe0d); u16(&config, contents.Len()); config.Write(contents.Bytes())
    u16(&list, config.Len()); list.Write(config.Bytes())
    return list.Bytes(), nil
}

func handshake(host string, config []byte) (bool, []byte, error) {
    conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 8 * time.Second}, "tcp", net.JoinHostPort(host,"443"), &tls.Config{
        ServerName: host, MinVersion: tls.VersionTLS13,
        EncryptedClientHelloConfigList: config, NextProtos: []string{"h2","http/1.1"},
    })
    if err != nil {
        var rejection *tls.ECHRejectionError
        if errors.As(err, &rejection) { return false, rejection.RetryConfigList, err }
        return false, nil, err
    }
    defer conn.Close()
    return conn.ConnectionState().ECHAccepted, nil, nil
}

type result struct {
    Host string `json:"host"`
    Verified bool `json:"verified"`
    Source string `json:"source,omitempty"`
    ECH string `json:"ech,omitempty"`
    Error string `json:"error,omitempty"`
}

func probe(host string, legacy []byte) result {
    seeds := []struct { name string; data []byte }{{"legacy",legacy}}
    for _, publicName := range []string{"graph.facebook.com","ech-public.atmeta.com"} {
        seed, err := probeSeed(publicName)
        if err == nil { seeds = append(seeds, struct { name string; data []byte }{publicName,seed}) }
    }
    last := "no accepted ECH configuration"
    for _, seed := range seeds {
        if len(seed.data)==0 { continue }
        accepted, retry, err := handshake(host,seed.data)
        if accepted { return result{Host:host,Verified:true,Source:seed.name,ECH:base64.StdEncoding.EncodeToString(seed.data)} }
        if err != nil { last = err.Error() }
        if len(retry)==0 { continue }
        accepted, _, err = handshake(host,retry)
        if accepted { return result{Host:host,Verified:true,Source:"authenticated-retry:"+seed.name,ECH:base64.StdEncoding.EncodeToString(retry)} }
        if err != nil { last=err.Error() }
    }
    return result{Host:host,Error:last}
}

func main() {
    src, err := os.ReadFile("_worker.js")
    if err != nil { panic(err) }
    match := regexp.MustCompile(`const META_ECH_CONFIG = "([^"]+)"`).FindSubmatch(src)
    if len(match)!=2 { panic("legacy config not found") }
    legacy, err := base64.StdEncoding.DecodeString(string(match[1]))
    if err != nil { panic(err) }
    hosts := []string{"www.facebook.com","graph.facebook.com","www.instagram.com"}
    out := make(chan result,len(hosts))
    for _, host := range hosts { go func(h string){ out <- probe(h,legacy) }(host) }
    results := make([]result,0,len(hosts))
    for range hosts {
        r := <-out
        results = append(results,r)
        fmt.Printf("%s verified=%t source=%s error=%s\n",r.Host,r.Verified,r.Source,r.Error)
    }
    data, err := json.MarshalIndent(results,"","  ")
    if err != nil { panic(err) }
    if err := os.WriteFile("meta-ech-probe.json",data,0600); err != nil { panic(err) }
}
