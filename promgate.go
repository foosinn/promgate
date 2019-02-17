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
	urls      []string
	listen    string
	certFile  string
	certKey   string
	clientCAs *x509.CertPool
	crl       *pkix.CertificateList
}

var (
	config configStore
	re     *regexp.Regexp
)

func init() {
	urls := getEnv("URLS", "http://localhost:9100")
	listen := getEnv("LISTEN", "0.0.0.0:9443")

	caFile := getEnv("CA", "")
	caData, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatal("Unable to load ca from $CA.")
	}
	clientCAs := x509.NewCertPool()
	if ok := clientCAs.AppendCertsFromPEM(caData); !ok {
		log.Fatal("Unable to parse $CA as ca.")

	}

	crlFile := getEnv("CRL", "")
	crlData, err := ioutil.ReadFile(crlFile)
	if err != nil {
		log.Fatal("Unable to load crl from $CRL.")
	}
	crl, err := x509.ParseCRL(crlData)
	if err != nil {
		log.Fatal("Unable to parse $CRL as crl.")
	}

	certFile := getEnv("CERT", "")
	keyFile := getEnv("KEY", "")

	config = configStore{
		strings.Split(urls, ","),
		listen,
		certFile,
		keyFile,
		clientCAs,
		crl,
	}

	re = regexp.MustCompile("^(?P<name>[^#][^ {]+)({(?P<labels>.*)})? (?P<value>.*)")
}

func main() {
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
	for _, url := range config.urls {
		wg.Add(1)
		go fetch(url, c, ctx, &wg)
	}
	go func() {
		wg.Wait()
		close(c)
	}()

	for res := range c {
		fmt.Fprintf(w, "%s\n", res)
	}
}

func extend(line string, source string) (string, error) {
	url, err := url.Parse(source)
	if err != nil {
		return line, err
	}
	label := fmt.Sprintf("%s%s", url.Host, url.Path)

	match := re.FindStringSubmatch(line)
	if len(match) != 5 {
		return line, errors.New("Invalid Line.")
	}

	lineName := match[1]
	lineLabels := match[3]
	lineValue := match[4]
	if lineLabels == "" {
		lineLabels = fmt.Sprintf("sub_instance=\"%s\"", label)
	} else {
		lineLabels = fmt.Sprintf("%s,sub_instance=\"%s\"", lineLabels, label)
	}
	line = fmt.Sprintf("%s{%s} %s", lineName, lineLabels, lineValue)
	return line, nil
}

func fetch(url string, c chan string, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Request Error %s.", err)
		return
	}
	req = req.WithContext(ctx)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Context Error %s.", err)
		return
	}
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		line, err = extend(line, url)
		c <- line
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Scanner Error %s.", err)
	}
}
