package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type configStore struct {
	urls   []*url.URL
	listen string

	disableTLS bool
	certFile   string
	certKey    string
	clientCAs  *x509.CertPool
	crl        *pkix.CertificateList
}

var (
	config configStore
	re     *regexp.Regexp
)

func init() {
	urlsString := getEnv("URLS", "http://localhost:9100/metrics")
	urls := []*url.URL{}
	for _, urlString := range strings.Split(urlsString, ",") {
		u, err := url.Parse(urlString)
		if err != nil {
			log.Fatal(err)
		}
		urls = append(urls, u)
	}

	listen := getEnv("LISTEN", "0.0.0.0:9443")
	_, disableTLS := os.LookupEnv("DISABLE_TLS")

	certFile := ""
	keyFile := ""
	clientCAs := x509.NewCertPool()
	crl := &pkix.CertificateList{}

	if !disableTLS {
		caFile := getEnv("CA", "")
		caData, err := ioutil.ReadFile(caFile)
		if err != nil {
			log.Fatal("Unable to load ca from $CA.")
		}
		if ok := clientCAs.AppendCertsFromPEM(caData); !ok {
			log.Fatal("Unable to parse $CA as ca.")

		}

		crlFile := getEnv("CRL", "")
		crlData, err := ioutil.ReadFile(crlFile)
		if err != nil {
			log.Fatal("Unable to load crl from $CRL.")
		}
		crl, err = x509.ParseCRL(crlData)
		if err != nil {
			log.Fatal("Unable to parse $CRL as crl.")
		}

		certFile = getEnv("CERT", "")
		keyFile = getEnv("KEY", "")
	}

	config = configStore{
		urls,
		listen,
		disableTLS,
		certFile,
		keyFile,
		clientCAs,
		crl,
	}

	re = regexp.MustCompile("^(?P<name>[^#][^ {]+)(?:{(?P<labels>.*)})? (?P<value>[0-9]+(?:\\.[0-9]+)?)")
}

func main() {
	if config.disableTLS {
		log.Printf("Running WITHOUT TLS!")
		http.HandleFunc("/metrics", metrics)
		s := &http.Server{Addr: config.listen}
		log.Fatal(s.ListenAndServe())
	} else {
		tlsConfig := &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  config.clientCAs,
		}
		s := &http.Server{
			Addr:      config.listen,
			TLSConfig: tlsConfig,
		}
		http.HandleFunc("/metrics", withTlsClientCheck(metrics))
		log.Fatal(s.ListenAndServeTLS(config.certFile, config.certKey))
	}
}

func getEnv(key string, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func withTlsClientCheck(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, peer := range r.TLS.PeerCertificates {
			for _, revoked := range config.crl.TBSCertList.RevokedCertificates {
				if peer.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
					log.Printf("Revoked certificate: ", peer.Subject)
					w.WriteHeader(403)
					return
				}
			}

		}
		next.ServeHTTP(w, r)
	}
}

func metrics(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	w.WriteHeader(200)

	c := make(chan string)
	var wg sync.WaitGroup
	for _, urlParsed := range config.urls {
		wg.Add(1)
		go fetch(urlParsed, c, ctx, &wg)
	}
	go func() {
		wg.Wait()
		close(c)
	}()

	for res := range c {
		fmt.Fprintf(w, "%s\n", res)
	}
}

func extend(line string, label string) (string, error) {

	match := re.FindStringSubmatch(line)
	if len(match) != 4 {
		return line, errors.New("Invalid Line.")
	}

	lineName := match[1]
	lineLabels := match[2]
	lineValue := match[3]
	if lineLabels == "" {
		lineLabels = fmt.Sprintf("sub_instance=\"%s\"", label)
	} else {
		lineLabels = fmt.Sprintf("%s,sub_instance=\"%s\"", lineLabels, label)
	}
	line = fmt.Sprintf("%s{%s} %s", lineName, lineLabels, lineValue)
	return line, nil
}

func fetch(u *url.URL, c chan string, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	urlString := u.String()
	label := fmt.Sprintf("%s%s", u.Host, u.Path)

	up := 0
	err := error(nil)
	defer func() {
		c <- fmt.Sprintf("up {sub_instance=\"%s\"} %d", label, up)
		if err != nil {
			log.Printf("Error: %s", err)
		}
	}()

	req, err := http.NewRequest("GET", urlString, nil)
	if err != nil {
		return
	}
	req = req.WithContext(ctx)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		line, err = extend(line, label)
		c <- line
	}
	if err := scanner.Err(); err != nil {
		return
	}
	up = 1
}
