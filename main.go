package main

import (
	"flag"
	"os"
	"fmt"
	"io/ioutil"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"crypto/rand"
	"crypto"
	"path/filepath"
)

func die(error ...interface{}) {
	fmt.Fprint(os.Stderr, "[ ERROR ] ")
	fmt.Fprintln(os.Stderr, error...)
	os.Exit(1)
}

func main() {
	newKey := flag.Bool("nk", false, "Generate new RSA key")
	keyOut := flag.String("ko", ".", "New key output dir")
	certOut := flag.String("co", ".", "New certificate output dir")
	keyBits := flag.Uint("kb", 2048, "Key bits if generating new key")
	flag.Parse()
  if len(flag.Args()) == 0 {
    flag.Usage()
  }
	if !(*keyBits > 128 && (*keyBits&(*keyBits-1) == 0)) {
		die("KeyBits must power of 2 & >= 128")
	}
	if e := os.Mkdir(*keyOut, 0700); e != nil {
		if !os.IsExist(e) {
			die("Can't create dir (", *keyOut, "): ", e.Error())
		}
	}
	if e := os.Mkdir(*certOut, 0700); e != nil {
		if !os.IsExist(e) {
			die("Can't create dir (", *certOut, "): ", e.Error())
		}
	}

	for _, dir := range flag.Args() {
		if stat, e := os.Stat(dir); e == nil {
			if !stat.IsDir() {
				die(dir, ": is not a directory")
			}
			if stat, e := os.Stat(getCertPath(dir, false)); e == nil {
				if stat.IsDir() || stat.Size() < 1024 {
					die(dir, " has wrong crt file")
				}
			} else {
				die(dir, ": can't find crt file")
			}
			if !*newKey {
				if stat, e := os.Stat(getCertPath(dir, true)); e == nil {
					if stat.IsDir() || stat.Size() < 1024 {
						die(dir, ": has wrong key file")
					}
				} else {
					die(dir, ": can't find key file")
				}
			}
			createFakieCert(dir, *keyOut, *certOut, *newKey, *keyBits)
		} else {
			die(" can't stat", dir, e.Error())
		}
	}
}
func getCertName(dir string) string {
	return filepath.Base(dir)
}

func getCertPath(dir string, isKey bool) string {
	var ext string
	if isKey {
		ext = "key"
	} else {
		ext = "crt"
	}
	x := filepath.Join(dir, fmt.Sprintf("%s.%s", getCertName(dir), ext))
	fmt.Println(x)
	return x
}

func createFakieCert(dir, keyOut, certOut string, newKey bool, keyBits uint) {
	certName := getCertName(dir)
	fmt.Println("[ INFO ] processing ", certName)
	certBytes, e := ioutil.ReadFile(getCertPath(dir, false))
	if e != nil {
		die(certName, ": can't read() certificate file: ", e.Error())
	}
	certPem, rest := pem.Decode(certBytes)
	if len(rest) != 0 {
		fmt.Println("[ WARNING ] Certificate chain detected. Only first one will be processed.")
	}
	x509cert, e := x509.ParseCertificate(certPem.Bytes)
	if e != nil {
		die(certName, ": can't parse certificate", e.Error())
	}
	var x509key interface{}
	if newKey {
		x509key, e = rsa.GenerateKey(rand.Reader, (int)(keyBits))
		if e != nil {
			die(certName, ": can't generate new key", e.Error())
		}
	} else {
		keyBytes, e := ioutil.ReadFile(getCertPath(dir, true))
		if e != nil {
			die(certName, ": can't read() private key", e.Error())
		}
		keyPem, rest := pem.Decode(keyBytes)
		if len(rest) != 0 {
			die(certName, ": bad private key")
		}
		x509key, e = x509.ParsePKCS8PrivateKey(keyPem.Bytes)
		if e != nil {
			die(certName, ": can't parse private key")
		}
	}
	newCert, e := x509.CreateCertificate(rand.Reader, x509cert, x509cert, x509key.(crypto.Signer).Public(), x509key)
	if e != nil {
		die(dir, "can't create new certificate", e.Error())
	}
	// write cert
	outKey, e := os.OpenFile(keyOut+"/"+certName+".key", os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		die(keyOut, ": can't create file for writing key")
	}
	p := pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(x509key.(*rsa.PrivateKey)),
		Type:  "RSA PRIVATE KEY",
	}
	pem.Encode(outKey, &p)
	outKey.Close()

	outCert, e := os.OpenFile(certOut+"/"+certName+".crt", os.O_CREATE|os.O_WRONLY, 0644)
	if e != nil {
		die(keyOut, ": can't create file for writing certificate")
	}
	p = pem.Block{
		Bytes: newCert,
		Type:  "CERTIFICATE",
	}
	pem.Encode(outCert, &p)
	outCert.Close()

}
