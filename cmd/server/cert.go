package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func httpGetTrim(u string, timeout time.Duration) string {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(u)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	ip := strings.TrimSpace(string(b))
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

// ensureCert 返回自签 TLS 证书与私钥路径；文件不存在时生成新的（ECDSA P-256，10 年有效）。
// 证书持久化到磁盘，服务重启后复用同一张，浏览器只需信任一次。
func ensureCert(certPath, keyPath string, extraIPs ...string) error {
	if fileExists(certPath) && fileExists(keyPath) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		return err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"iptun"},
			CommonName:   "iptun-admin",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // 自签根证书，便于导入系统信任库
		DNSNames:              []string{"localhost", "iptun"},
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
			net.ParseIP("::1"),
		},
	}
	for _, ipStr := range extraIPs {
		if ip := net.ParseIP(ipStr); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}
	return nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// detectPublicIPQuick 快速（最多 4 秒）探测公网 IP，用于写入证书 SAN；失败不阻断启动。
func detectPublicIPQuick() string {
	type result struct{ ip string }
	ch := make(chan result, 1)
	go func() {
		// 云元数据地址优先（最快、不依赖外网 DNS）
		for _, u := range []string{
			"http://metadata.tencentyun.com/latest/meta-data/public-ipv4",
			"http://100.100.100.200/latest/meta-data/eipv4",
		} {
			ip := httpGetTrim(u, 2*time.Second)
			if net.ParseIP(ip) != nil {
				ch <- result{ip}
				return
			}
		}
		ch <- result{}
	}()
	select {
	case r := <-ch:
		return r.ip
	case <-time.After(4 * time.Second):
		return ""
	}
}
