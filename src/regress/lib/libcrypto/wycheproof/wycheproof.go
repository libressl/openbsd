/* $OpenBSD: wycheproof.go,v 1.145 2023/04/25 15:56:56 tb Exp $ */
/*
 * Copyright (c) 2018 Joel Sing <jsing@openbsd.org>
 * Copyright (c) 2018,2019,2022 Theo Buehler <tb@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

// Wycheproof runs test vectors from Project Wycheproof against libcrypto.
package main

/*
#cgo LDFLAGS: -lcrypto

#include <limits.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/cmac.h>
#include <openssl/curve25519.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>

int
wp_EVP_PKEY_CTX_set_hkdf_md(EVP_PKEY_CTX *pctx, const EVP_MD *md)
{
	return EVP_PKEY_CTX_set_hkdf_md(pctx, md);
}

int
wp_EVP_PKEY_CTX_set1_hkdf_salt(EVP_PKEY_CTX *pctx, const unsigned char *salt, size_t salt_len)
{
	if (salt_len > INT_MAX)
		return 0;
	return EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len);
}

int
wp_EVP_PKEY_CTX_set1_hkdf_key(EVP_PKEY_CTX *pctx, const unsigned char *ikm, size_t ikm_len)
{
	if (ikm_len > INT_MAX)
		return 0;
	return EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, ikm_len);
}

int
wp_EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX *pctx, const unsigned char *info, size_t info_len)
{
	if (info_len > INT_MAX)
		return 0;
	return EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len);
}
*/
import "C"

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"unsafe"
)

const testVectorPath = "/usr/local/share/wycheproof/testvectors"

type testVariant int

const (
	Normal    testVariant = 0
	EcPoint   testVariant = 1
	P1363     testVariant = 2
	Webcrypto testVariant = 3
	Asn1      testVariant = 4
	Pem       testVariant = 5
	Jwk       testVariant = 6
	Skip      testVariant = 7
)

func (variant testVariant) String() string {
	variants := [...]string{
		"Normal",
		"EcPoint",
		"P1363",
		"Webcrypto",
		"Asn1",
		"Pem",
		"Jwk",
		"Skip",
	}
	return variants[variant]
}

var testc *testCoordinator

type wycheproofJWKPublic struct {
	Crv string `json:"crv"`
	KID string `json:"kid"`
	KTY string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type wycheproofJWKPrivate struct {
	Crv string `json:"crv"`
	D   string `json:"d"`
	KID string `json:"kid"`
	KTY string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type wycheproofTestGroupAesCbcPkcs5 struct {
	IVSize  int                          `json:"ivSize"`
	KeySize int                          `json:"keySize"`
	Type    string                       `json:"type"`
	Tests   []*wycheproofTestAesCbcPkcs5 `json:"tests"`
}

type wycheproofTestAesCbcPkcs5 struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Key     string   `json:"key"`
	IV      string   `json:"iv"`
	Msg     string   `json:"msg"`
	CT      string   `json:"ct"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type wycheproofTestGroupAead struct {
	IVSize  int                   `json:"ivSize"`
	KeySize int                   `json:"keySize"`
	TagSize int                   `json:"tagSize"`
	Type    string                `json:"type"`
	Tests   []*wycheproofTestAead `json:"tests"`
}

type wycheproofTestAead struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Key     string   `json:"key"`
	IV      string   `json:"iv"`
	AAD     string   `json:"aad"`
	Msg     string   `json:"msg"`
	CT      string   `json:"ct"`
	Tag     string   `json:"tag"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type wycheproofTestGroupAesCmac struct {
	KeySize int                      `json:"keySize"`
	TagSize int                      `json:"tagSize"`
	Type    string                   `json:"type"`
	Tests   []*wycheproofTestAesCmac `json:"tests"`
}

type wycheproofTestAesCmac struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Key     string   `json:"key"`
	Msg     string   `json:"msg"`
	Tag     string   `json:"tag"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type wycheproofDSAKey struct {
	G       string `json:"g"`
	KeySize int    `json:"keySize"`
	P       string `json:"p"`
	Q       string `json:"q"`
	Type    string `json:"type"`
	Y       string `json:"y"`
}

type wycheproofTestDSA struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Msg     string   `json:"msg"`
	Sig     string   `json:"sig"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type wycheproofTestGroupDSA struct {
	Key    *wycheproofDSAKey    `json:"key"`
	KeyDER string               `json:"keyDer"`
	KeyPEM string               `json:"keyPem"`
	SHA    string               `json:"sha"`
	Type   string               `json:"type"`
	Tests  []*wycheproofTestDSA `json:"tests"`
}

type wycheproofTestECDH struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Public  string   `json:"public"`
	Private string   `json:"private"`
	Shared  string   `json:"shared"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type wycheproofTestGroupECDH struct {
	Curve    string                `json:"curve"`
	Encoding string                `json:"encoding"`
	Type     string                `json:"type"`
	Tests    []*wycheproofTestECDH `json:"tests"`
}

type wycheproofTestECDHWebCrypto struct {
	TCID    int                   `json:"tcId"`
	Comment string                `json:"comment"`
	Public  *wycheproofJWKPublic  `json:"public"`
	Private *wycheproofJWKPrivate `json:"private"`
	Shared  string                `json:"shared"`
	Result  string                `json:"result"`
	Flags   []string              `json:"flags"`
}

type wycheproofTestGroupECDHWebCrypto struct {
	Curve    string                         `json:"curve"`
	Encoding string                         `json:"encoding"`
	Type     string                         `json:"type"`
	Tests    []*wycheproofTestECDHWebCrypto `json:"tests"`
}

type wycheproofECDSAKey struct {
	Curve        string `json:"curve"`
	KeySize      int    `json:"keySize"`
	Type         string `json:"type"`
	Uncompressed string `json:"uncompressed"`
	WX           string `json:"wx"`
	WY           string `json:"wy"`
}

type wycheproofTestECDSA struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Msg     string   `json:"msg"`
	Sig     string   `json:"sig"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type wycheproofTestGroupECDSA struct {
	Key    *wycheproofECDSAKey    `json:"key"`
	KeyDER string                 `json:"keyDer"`
	KeyPEM string                 `json:"keyPem"`
	SHA    string                 `json:"sha"`
	Type   string                 `json:"type"`
	Tests  []*wycheproofTestECDSA `json:"tests"`
}

type wycheproofTestGroupECDSAWebCrypto struct {
	JWK    *wycheproofJWKPublic   `json:"jwk"`
	Key    *wycheproofECDSAKey    `json:"key"`
	KeyDER string                 `json:"keyDer"`
	KeyPEM string                 `json:"keyPem"`
	SHA    string                 `json:"sha"`
	Type   string                 `json:"type"`
	Tests  []*wycheproofTestECDSA `json:"tests"`
}

type wycheproofJWKEdDSA struct {
	Crv string `json:"crv"`
	D   string `json:"d"`
	KID string `json:"kid"`
	KTY string `json:"kty"`
	X   string `json:"x"`
}

type wycheproofEdDSAKey struct {
	Curve   string `json:"curve"`
	KeySize int    `json:"keySize"`
	Pk      string `json:"pk"`
	Sk      string `json:"sk"`
	Type    string `json:"type"`
}

type wycheproofTestEdDSA struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Msg     string   `json:"msg"`
	Sig     string   `json:"sig"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type wycheproofTestGroupEdDSA struct {
	JWK    *wycheproofJWKEdDSA    `json:"jwk"`
	Key    *wycheproofEdDSAKey    `json:"key"`
	KeyDer string                 `json:"keyDer"`
	KeyPem string                 `json:"keyPem"`
	Type   string                 `json:"type"`
	Tests  []*wycheproofTestEdDSA `json:"tests"`
}

type wycheproofTestHkdf struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Ikm     string   `json:"ikm"`
	Salt    string   `json:"salt"`
	Info    string   `json:"info"`
	Size    int      `json:"size"`
	Okm     string   `json:"okm"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type wycheproofTestGroupHkdf struct {
	Type    string                `json:"type"`
	KeySize int                   `json:"keySize"`
	Tests   []*wycheproofTestHkdf `json:"tests"`
}

type wycheproofTestHmac struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Key     string   `json:"key"`
	Msg     string   `json:"msg"`
	Tag     string   `json:"tag"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type wycheproofTestGroupHmac struct {
	KeySize int                   `json:"keySize"`
	TagSize int                   `json:"tagSize"`
	Type    string                `json:"type"`
	Tests   []*wycheproofTestHmac `json:"tests"`
}

type wycheproofTestKW struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Key     string   `json:"key"`
	Msg     string   `json:"msg"`
	CT      string   `json:"ct"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type wycheproofTestGroupKW struct {
	KeySize int                 `json:"keySize"`
	Type    string              `json:"type"`
	Tests   []*wycheproofTestKW `json:"tests"`
}

type wycheproofTestPrimality struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Value   string   `json:"value"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type wycheproofTestGroupPrimality struct {
	Type  string                     `json:"type"`
	Tests []*wycheproofTestPrimality `json:"tests"`
}

type wycheproofTestRSA struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Msg     string   `json:"msg"`
	Sig     string   `json:"sig"`
	Padding string   `json:"padding"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type wycheproofTestGroupRSA struct {
	E       string               `json:"e"`
	KeyASN  string               `json:"keyAsn"`
	KeyDER  string               `json:"keyDer"`
	KeyPEM  string               `json:"keyPem"`
	KeySize int                  `json:"keysize"`
	N       string               `json:"n"`
	SHA     string               `json:"sha"`
	Type    string               `json:"type"`
	Tests   []*wycheproofTestRSA `json:"tests"`
}

type wycheproofPrivateKeyJwk struct {
	Alg string `json:"alg"`
	D   string `json:"d"`
	DP  string `json:"dp"`
	DQ  string `json:"dq"`
	E   string `json:"e"`
	KID string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	P   string `json:"p"`
	Q   string `json:"q"`
	QI  string `json:"qi"`
}

type wycheproofTestRsaes struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Msg     string   `json:"msg"`
	CT      string   `json:"ct"`
	Label   string   `json:"label"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type wycheproofTestGroupRsaesOaep struct {
	D               string                   `json:"d"`
	E               string                   `json:"e"`
	KeySize         int                      `json:"keysize"`
	MGF             string                   `json:"mgf"`
	MGFSHA          string                   `json:"mgfSha"`
	N               string                   `json:"n"`
	PrivateKeyJwk   *wycheproofPrivateKeyJwk `json:"privateKeyJwk"`
	PrivateKeyPem   string                   `json:"privateKeyPem"`
	PrivateKeyPkcs8 string                   `json:"privateKeyPkcs8"`
	SHA             string                   `json:"sha"`
	Type            string                   `json:"type"`
	Tests           []*wycheproofTestRsaes   `json:"tests"`
}

type wycheproofTestGroupRsaesPkcs1 struct {
	D               string                   `json:"d"`
	E               string                   `json:"e"`
	KeySize         int                      `json:"keysize"`
	N               string                   `json:"n"`
	PrivateKeyJwk   *wycheproofPrivateKeyJwk `json:"privateKeyJwk"`
	PrivateKeyPem   string                   `json:"privateKeyPem"`
	PrivateKeyPkcs8 string                   `json:"privateKeyPkcs8"`
	Type            string                   `json:"type"`
	Tests           []*wycheproofTestRsaes   `json:"tests"`
}

type wycheproofTestRsassa struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Msg     string   `json:"msg"`
	Sig     string   `json:"sig"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type wycheproofTestGroupRsassa struct {
	E       string                  `json:"e"`
	KeyASN  string                  `json:"keyAsn"`
	KeyDER  string                  `json:"keyDer"`
	KeyPEM  string                  `json:"keyPem"`
	KeySize int                     `json:"keysize"`
	MGF     string                  `json:"mgf"`
	MGFSHA  string                  `json:"mgfSha"`
	N       string                  `json:"n"`
	SLen    int                     `json:"sLen"`
	SHA     string                  `json:"sha"`
	Type    string                  `json:"type"`
	Tests   []*wycheproofTestRsassa `json:"tests"`
}

type wycheproofTestX25519 struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Curve   string   `json:"curve"`
	Public  string   `json:"public"`
	Private string   `json:"private"`
	Shared  string   `json:"shared"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type wycheproofTestGroupX25519 struct {
	Curve string                  `json:"curve"`
	Tests []*wycheproofTestX25519 `json:"tests"`
}

type wycheproofTestVectors struct {
	Algorithm        string            `json:"algorithm"`
	GeneratorVersion string            `json:"generatorVersion"`
	Notes            map[string]string `json:"notes"`
	NumberOfTests    int               `json:"numberOfTests"`
	// Header
	TestGroups []json.RawMessage `json:"testGroups"`
}

var nids = map[string]int{
	"brainpoolP224r1": C.NID_brainpoolP224r1,
	"brainpoolP256r1": C.NID_brainpoolP256r1,
	"brainpoolP320r1": C.NID_brainpoolP320r1,
	"brainpoolP384r1": C.NID_brainpoolP384r1,
	"brainpoolP512r1": C.NID_brainpoolP512r1,
	"brainpoolP224t1": C.NID_brainpoolP224t1,
	"brainpoolP256t1": C.NID_brainpoolP256t1,
	"brainpoolP320t1": C.NID_brainpoolP320t1,
	"brainpoolP384t1": C.NID_brainpoolP384t1,
	"brainpoolP512t1": C.NID_brainpoolP512t1,
	"FRP256v1":        C.NID_FRP256v1,
	"secp160k1":       C.NID_secp160k1,
	"secp160r1":       C.NID_secp160r1,
	"secp160r2":       C.NID_secp160r2,
	"secp192k1":       C.NID_secp192k1,
	"secp192r1":       C.NID_X9_62_prime192v1, // RFC 8422, Table 4, p.32
	"secp224k1":       C.NID_secp224k1,
	"secp224r1":       C.NID_secp224r1,
	"secp256k1":       C.NID_secp256k1,
	"P-256K":          C.NID_secp256k1,
	"secp256r1":       C.NID_X9_62_prime256v1, // RFC 8422, Table 4, p.32
	"P-256":           C.NID_X9_62_prime256v1,
	"sect283k1":       C.NID_sect283k1,
	"sect283r1":       C.NID_sect283r1,
	"secp384r1":       C.NID_secp384r1,
	"P-384":           C.NID_secp384r1,
	"sect409k1":       C.NID_sect409k1,
	"sect409r1":       C.NID_sect409r1,
	"secp521r1":       C.NID_secp521r1,
	"sect571k1":       C.NID_sect571k1,
	"sect571r1":       C.NID_sect571r1,
	"P-521":           C.NID_secp521r1,
	"SHA-1":           C.NID_sha1,
	"SHA-224":         C.NID_sha224,
	"SHA-256":         C.NID_sha256,
	"SHA-384":         C.NID_sha384,
	"SHA-512":         C.NID_sha512,
	"SHA-512/224":     C.NID_sha512_224,
	"SHA-512/256":     C.NID_sha512_256,
	"SHA3-224":        C.NID_sha3_224,
	"SHA3-256":        C.NID_sha3_256,
	"SHA3-384":        C.NID_sha3_384,
	"SHA3-512":        C.NID_sha3_512,
}

func nidFromString(ns string) (int, error) {
	nid, ok := nids[ns]
	if ok {
		return nid, nil
	}
	return -1, fmt.Errorf("unknown NID %q", ns)
}

func hashEvpMdFromString(hs string) (*C.EVP_MD, error) {
	switch hs {
	case "SHA-1":
		return C.EVP_sha1(), nil
	case "SHA-224":
		return C.EVP_sha224(), nil
	case "SHA-256":
		return C.EVP_sha256(), nil
	case "SHA-384":
		return C.EVP_sha384(), nil
	case "SHA-512":
		return C.EVP_sha512(), nil
	case "SHA-512/224":
		return C.EVP_sha512_224(), nil
	case "SHA-512/256":
		return C.EVP_sha512_256(), nil
	case "SHA3-224":
		return C.EVP_sha3_224(), nil
	case "SHA3-256":
		return C.EVP_sha3_256(), nil
	case "SHA3-384":
		return C.EVP_sha3_384(), nil
	case "SHA3-512":
		return C.EVP_sha3_512(), nil
	default:
		return nil, fmt.Errorf("unknown hash %q", hs)
	}
}

func hashEvpDigestMessage(md *C.EVP_MD, msg []byte) ([]byte, int, error) {
	size := C.EVP_MD_size(md)
	if size <= 0 || size > C.EVP_MAX_MD_SIZE {
		return nil, 0, fmt.Errorf("unexpected MD size %d", size)
	}

	msgLen := len(msg)
	if msgLen == 0 {
		msg = append(msg, 0)
	}

	digest := make([]byte, size)

	if C.EVP_Digest(unsafe.Pointer(&msg[0]), C.size_t(msgLen), (*C.uchar)(unsafe.Pointer(&digest[0])), nil, md, nil) != 1 {
		return nil, 0, fmt.Errorf("EVP_Digest failed")
	}

	return digest, int(size), nil
}

func checkAesCbcPkcs5(ctx *C.EVP_CIPHER_CTX, doEncrypt int, key []byte, keyLen int,
	iv []byte, ivLen int, in []byte, inLen int, out []byte, outLen int,
	wt *wycheproofTestAesCbcPkcs5) bool {
	var action string
	if doEncrypt == 1 {
		action = "encrypting"
	} else {
		action = "decrypting"
	}

	ret := C.EVP_CipherInit_ex(ctx, nil, nil, (*C.uchar)(unsafe.Pointer(&key[0])),
		(*C.uchar)(unsafe.Pointer(&iv[0])), C.int(doEncrypt))
	if ret != 1 {
		log.Fatalf("EVP_CipherInit_ex failed: %d", ret)
	}

	cipherOut := make([]byte, inLen+C.EVP_MAX_BLOCK_LENGTH)
	var cipherOutLen C.int

	ret = C.EVP_CipherUpdate(ctx, (*C.uchar)(unsafe.Pointer(&cipherOut[0])), &cipherOutLen,
		(*C.uchar)(unsafe.Pointer(&in[0])), C.int(inLen))
	if ret != 1 {
		if wt.Result == "invalid" {
			fmt.Printf("INFO: Test case %d (%q) [%v] %v - EVP_CipherUpdate() = %d, want %v\n",
				wt.TCID, wt.Comment, action, wt.Flags, ret, wt.Result)
			return true
		}
		fmt.Printf("FAIL: Test case %d (%q) [%v] %v - EVP_CipherUpdate() = %d, want %v\n",
			wt.TCID, wt.Comment, action, wt.Flags, ret, wt.Result)
		return false
	}

	var finallen C.int
	ret = C.EVP_CipherFinal_ex(ctx, (*C.uchar)(unsafe.Pointer(&cipherOut[cipherOutLen])), &finallen)
	if ret != 1 {
		if wt.Result == "invalid" {
			return true
		}
		fmt.Printf("FAIL: Test case %d (%q) [%v] %v - EVP_CipherFinal_ex() = %d, want %v\n",
			wt.TCID, wt.Comment, action, wt.Flags, ret, wt.Result)
		return false
	}

	cipherOutLen += finallen
	if cipherOutLen != C.int(outLen) && wt.Result != "invalid" {
		fmt.Printf("FAIL: Test case %d (%q) [%v] %v - open length mismatch: got %d, want %d\n",
			wt.TCID, wt.Comment, action, wt.Flags, cipherOutLen, outLen)
		return false
	}

	openedMsg := cipherOut[0:cipherOutLen]
	if outLen == 0 {
		out = nil
	}

	success := false
	if bytes.Equal(openedMsg, out) == (wt.Result != "invalid") {
		success = true
	} else {
		fmt.Printf("FAIL: Test case %d (%q) [%v] %v - msg match: %t; want %v\n",
			wt.TCID, wt.Comment, action, wt.Flags, bytes.Equal(openedMsg, out), wt.Result)
	}
	return success
}

func runAesCbcPkcs5Test(ctx *C.EVP_CIPHER_CTX, wt *wycheproofTestAesCbcPkcs5) bool {
	key, err := hex.DecodeString(wt.Key)
	if err != nil {
		log.Fatalf("Failed to decode key %q: %v", wt.Key, err)
	}
	iv, err := hex.DecodeString(wt.IV)
	if err != nil {
		log.Fatalf("Failed to decode IV %q: %v", wt.IV, err)
	}
	ct, err := hex.DecodeString(wt.CT)
	if err != nil {
		log.Fatalf("Failed to decode CT %q: %v", wt.CT, err)
	}
	msg, err := hex.DecodeString(wt.Msg)
	if err != nil {
		log.Fatalf("Failed to decode message %q: %v", wt.Msg, err)
	}

	keyLen, ivLen, ctLen, msgLen := len(key), len(iv), len(ct), len(msg)

	if keyLen == 0 {
		key = append(key, 0)
	}
	if ivLen == 0 {
		iv = append(iv, 0)
	}
	if ctLen == 0 {
		ct = append(ct, 0)
	}
	if msgLen == 0 {
		msg = append(msg, 0)
	}

	openSuccess := checkAesCbcPkcs5(ctx, 0, key, keyLen, iv, ivLen, ct, ctLen, msg, msgLen, wt)
	sealSuccess := checkAesCbcPkcs5(ctx, 1, key, keyLen, iv, ivLen, msg, msgLen, ct, ctLen, wt)

	return openSuccess && sealSuccess
}

func runAesCbcPkcs5TestGroup(algorithm string, wtg *wycheproofTestGroupAesCbcPkcs5) bool {
	fmt.Printf("Running %v test group %v with IV size %d and key size %d...\n",
		algorithm, wtg.Type, wtg.IVSize, wtg.KeySize)

	var cipher *C.EVP_CIPHER
	switch wtg.KeySize {
	case 128:
		cipher = C.EVP_aes_128_cbc()
	case 192:
		cipher = C.EVP_aes_192_cbc()
	case 256:
		cipher = C.EVP_aes_256_cbc()
	default:
		log.Fatalf("Unsupported key size: %d", wtg.KeySize)
	}

	ctx := C.EVP_CIPHER_CTX_new()
	if ctx == nil {
		log.Fatal("EVP_CIPHER_CTX_new() failed")
	}
	defer C.EVP_CIPHER_CTX_free(ctx)

	ret := C.EVP_CipherInit_ex(ctx, cipher, nil, nil, nil, 0)
	if ret != 1 {
		log.Fatalf("EVP_CipherInit_ex failed: %d", ret)
	}

	success := true
	for _, wt := range wtg.Tests {
		if !runAesCbcPkcs5Test(ctx, wt) {
			success = false
		}
	}
	return success
}

func checkAesAead(algorithm string, ctx *C.EVP_CIPHER_CTX, doEncrypt int,
	key []byte, keyLen int, iv []byte, ivLen int, aad []byte, aadLen int,
	in []byte, inLen int, out []byte, outLen int, tag []byte, tagLen int,
	wt *wycheproofTestAead) bool {
	var ctrlSetIVLen C.int
	var ctrlSetTag C.int
	var ctrlGetTag C.int

	doCCM := false
	switch algorithm {
	case "AES-CCM":
		doCCM = true
		ctrlSetIVLen = C.EVP_CTRL_CCM_SET_IVLEN
		ctrlSetTag = C.EVP_CTRL_CCM_SET_TAG
		ctrlGetTag = C.EVP_CTRL_CCM_GET_TAG
	case "AES-GCM":
		ctrlSetIVLen = C.EVP_CTRL_GCM_SET_IVLEN
		ctrlSetTag = C.EVP_CTRL_GCM_SET_TAG
		ctrlGetTag = C.EVP_CTRL_GCM_GET_TAG
	}

	setTag := unsafe.Pointer(nil)
	var action string

	if doEncrypt == 1 {
		action = "encrypting"
	} else {
		action = "decrypting"
		setTag = unsafe.Pointer(&tag[0])
	}

	ret := C.EVP_CipherInit_ex(ctx, nil, nil, nil, nil, C.int(doEncrypt))
	if ret != 1 {
		log.Fatalf("[%v] cipher init failed", action)
	}

	ret = C.EVP_CIPHER_CTX_ctrl(ctx, ctrlSetIVLen, C.int(ivLen), nil)
	if ret != 1 {
		if wt.Comment == "Nonce is too long" || wt.Comment == "Invalid nonce size" ||
			wt.Comment == "0 size IV is not valid" || wt.Comment == "Very long nonce" {
			return true
		}
		fmt.Printf("FAIL: Test case %d (%q) [%v] %v - setting IV len to %d failed. got %d, want %v\n",
			wt.TCID, wt.Comment, action, wt.Flags, ivLen, ret, wt.Result)
		return false
	}

	if doEncrypt == 0 || doCCM {
		ret = C.EVP_CIPHER_CTX_ctrl(ctx, ctrlSetTag, C.int(tagLen), setTag)
		if ret != 1 {
			if wt.Comment == "Invalid tag size" {
				return true
			}
			fmt.Printf("FAIL: Test case %d (%q) [%v] %v - setting tag length to %d failed. got %d, want %v\n",
				wt.TCID, wt.Comment, action, wt.Flags, tagLen, ret, wt.Result)
			return false
		}
	}

	ret = C.EVP_CipherInit_ex(ctx, nil, nil, (*C.uchar)(unsafe.Pointer(&key[0])),
		(*C.uchar)(unsafe.Pointer(&iv[0])), C.int(doEncrypt))
	if ret != 1 {
		fmt.Printf("FAIL: Test case %d (%q) [%v] %v - setting key and IV failed. got %d, want %v\n",
			wt.TCID, wt.Comment, action, wt.Flags, ret, wt.Result)
		return false
	}

	var cipherOutLen C.int
	if doCCM {
		ret = C.EVP_CipherUpdate(ctx, nil, &cipherOutLen, nil, C.int(inLen))
		if ret != 1 {
			fmt.Printf("FAIL: Test case %d (%q) [%v] %v - setting input length to %d failed. got %d, want %v\n",
				wt.TCID, wt.Comment, action, wt.Flags, inLen, ret, wt.Result)
			return false
		}
	}

	ret = C.EVP_CipherUpdate(ctx, nil, &cipherOutLen, (*C.uchar)(unsafe.Pointer(&aad[0])), C.int(aadLen))
	if ret != 1 {
		fmt.Printf("FAIL: Test case %d (%q) [%v] %v - processing AAD failed. got %d, want %v\n",
			wt.TCID, wt.Comment, action, wt.Flags, ret, wt.Result)
		return false
	}

	cipherOutLen = 0
	cipherOut := make([]byte, inLen)
	if inLen == 0 {
		cipherOut = append(cipherOut, 0)
	}

	ret = C.EVP_CipherUpdate(ctx, (*C.uchar)(unsafe.Pointer(&cipherOut[0])), &cipherOutLen,
		(*C.uchar)(unsafe.Pointer(&in[0])), C.int(inLen))
	if ret != 1 {
		if wt.Result == "invalid" {
			return true
		}
		fmt.Printf("FAIL: Test case %d (%q) [%v] %v - EVP_CipherUpdate() = %d, want %v\n",
			wt.TCID, wt.Comment, action, wt.Flags, ret, wt.Result)
		return false
	}

	if doEncrypt == 1 {
		var tmpLen C.int
		dummyOut := make([]byte, 16)

		ret = C.EVP_CipherFinal_ex(ctx, (*C.uchar)(unsafe.Pointer(&dummyOut[0])), &tmpLen)
		if ret != 1 {
			fmt.Printf("FAIL: Test case %d (%q) [%v] %v - EVP_CipherFinal_ex() = %d, want %v\n",
				wt.TCID, wt.Comment, action, wt.Flags, ret, wt.Result)
			return false
		}
		cipherOutLen += tmpLen
	}

	if cipherOutLen != C.int(outLen) {
		fmt.Printf("FAIL: Test case %d (%q) [%v] %v - cipherOutLen %d != outLen %d. Result %v\n",
			wt.TCID, wt.Comment, action, wt.Flags, cipherOutLen, outLen, wt.Result)
		return false
	}

	success := true
	if !bytes.Equal(cipherOut, out) {
		fmt.Printf("FAIL: Test case %d (%q) [%v] %v - expected and computed output do not match. Result: %v\n",
			wt.TCID, wt.Comment, action, wt.Flags, wt.Result)
		success = false
	}
	if doEncrypt == 1 {
		tagOut := make([]byte, tagLen)
		ret = C.EVP_CIPHER_CTX_ctrl(ctx, ctrlGetTag, C.int(tagLen), unsafe.Pointer(&tagOut[0]))
		if ret != 1 {
			fmt.Printf("FAIL: Test case %d (%q) [%v] %v - EVP_CIPHER_CTX_ctrl() = %d, want %v\n",
				wt.TCID, wt.Comment, action, wt.Flags, ret, wt.Result)
			return false
		}

		// There are no acceptable CCM cases. All acceptable GCM tests
		// pass. They have len(IV) <= 48. NIST SP 800-38D, 5.2.1.1, p.8,
		// allows 1 <= len(IV) <= 2^64-1, but notes:
		//   "For IVs it is recommended that implementations restrict
		//    support to the length of 96 bits, to promote
		//    interoperability, efficiency and simplicity of design."
		if bytes.Equal(tagOut, tag) != (wt.Result == "valid" || wt.Result == "acceptable") {
			fmt.Printf("FAIL: Test case %d (%q) [%v] %v - expected and computed tag do not match - ret: %d, Result: %v\n",
				wt.TCID, wt.Comment, action, wt.Flags, ret, wt.Result)
			success = false
		}
	}
	return success
}

func runAesAeadTest(algorithm string, ctx *C.EVP_CIPHER_CTX, aead *C.EVP_AEAD, wt *wycheproofTestAead) bool {
	key, err := hex.DecodeString(wt.Key)
	if err != nil {
		log.Fatalf("Failed to decode key %q: %v", wt.Key, err)
	}

	iv, err := hex.DecodeString(wt.IV)
	if err != nil {
		log.Fatalf("Failed to decode IV %q: %v", wt.IV, err)
	}

	aad, err := hex.DecodeString(wt.AAD)
	if err != nil {
		log.Fatalf("Failed to decode AAD %q: %v", wt.AAD, err)
	}

	msg, err := hex.DecodeString(wt.Msg)
	if err != nil {
		log.Fatalf("Failed to decode msg %q: %v", wt.Msg, err)
	}

	ct, err := hex.DecodeString(wt.CT)
	if err != nil {
		log.Fatalf("Failed to decode CT %q: %v", wt.CT, err)
	}

	tag, err := hex.DecodeString(wt.Tag)
	if err != nil {
		log.Fatalf("Failed to decode tag %q: %v", wt.Tag, err)
	}

	keyLen, ivLen, aadLen, msgLen, ctLen, tagLen := len(key), len(iv), len(aad), len(msg), len(ct), len(tag)

	if keyLen == 0 {
		key = append(key, 0)
	}
	if ivLen == 0 {
		iv = append(iv, 0)
	}
	if aadLen == 0 {
		aad = append(aad, 0)
	}
	if msgLen == 0 {
		msg = append(msg, 0)
	}
	if ctLen == 0 {
		ct = append(ct, 0)
	}
	if tagLen == 0 {
		tag = append(tag, 0)
	}

	openEvp := checkAesAead(algorithm, ctx, 0, key, keyLen, iv, ivLen, aad, aadLen, ct, ctLen, msg, msgLen, tag, tagLen, wt)
	sealEvp := checkAesAead(algorithm, ctx, 1, key, keyLen, iv, ivLen, aad, aadLen, msg, msgLen, ct, ctLen, tag, tagLen, wt)

	openAead, sealAead := true, true
	if aead != nil {
		ctx := C.EVP_AEAD_CTX_new()
		if ctx == nil {
			log.Fatal("EVP_AEAD_CTX_new() failed")
		}
		defer C.EVP_AEAD_CTX_free(ctx)

		if C.EVP_AEAD_CTX_init(ctx, aead, (*C.uchar)(unsafe.Pointer(&key[0])), C.size_t(keyLen), C.size_t(tagLen), nil) != 1 {
			log.Fatal("Failed to initialize AEAD context")
		}

		// Make sure we don't accidentally prepend or compare against a 0.
		if ctLen == 0 {
			ct = nil
		}

		openAead = checkAeadOpen(ctx, iv, ivLen, aad, aadLen, msg, msgLen, ct, ctLen, tag, tagLen, wt)
		sealAead = checkAeadSeal(ctx, iv, ivLen, aad, aadLen, msg, msgLen, ct, ctLen, tag, tagLen, wt)
	}

	return openEvp && sealEvp && openAead && sealAead
}

func runAesAeadTestGroup(algorithm string, wtg *wycheproofTestGroupAead) bool {
	fmt.Printf("Running %v test group %v with IV size %d, key size %d and tag size %d...\n",
		algorithm, wtg.Type, wtg.IVSize, wtg.KeySize, wtg.TagSize)

	var cipher *C.EVP_CIPHER
	var aead *C.EVP_AEAD
	switch algorithm {
	case "AES-CCM":
		switch wtg.KeySize {
		case 128:
			cipher = C.EVP_aes_128_ccm()
		case 192:
			cipher = C.EVP_aes_192_ccm()
		case 256:
			cipher = C.EVP_aes_256_ccm()
		default:
			fmt.Printf("INFO: Skipping tests with invalid key size %d\n", wtg.KeySize)
			return true
		}
	case "AES-GCM":
		switch wtg.KeySize {
		case 128:
			cipher = C.EVP_aes_128_gcm()
			aead = C.EVP_aead_aes_128_gcm()
		case 192:
			cipher = C.EVP_aes_192_gcm()
		case 256:
			cipher = C.EVP_aes_256_gcm()
			aead = C.EVP_aead_aes_256_gcm()
		default:
			fmt.Printf("INFO: Skipping tests with invalid key size %d\n", wtg.KeySize)
			return true
		}
	default:
		log.Fatalf("runAesAeadTestGroup() - unhandled algorithm: %v", algorithm)
	}

	ctx := C.EVP_CIPHER_CTX_new()
	if ctx == nil {
		log.Fatal("EVP_CIPHER_CTX_new() failed")
	}
	defer C.EVP_CIPHER_CTX_free(ctx)

	C.EVP_CipherInit_ex(ctx, cipher, nil, nil, nil, 1)

	success := true
	for _, wt := range wtg.Tests {
		if !runAesAeadTest(algorithm, ctx, aead, wt) {
			success = false
		}
	}
	return success
}

func runAesCmacTest(cipher *C.EVP_CIPHER, wt *wycheproofTestAesCmac) bool {
	key, err := hex.DecodeString(wt.Key)
	if err != nil {
		log.Fatalf("Failed to decode key %q: %v", wt.Key, err)
	}

	msg, err := hex.DecodeString(wt.Msg)
	if err != nil {
		log.Fatalf("Failed to decode msg %q: %v", wt.Msg, err)
	}

	tag, err := hex.DecodeString(wt.Tag)
	if err != nil {
		log.Fatalf("Failed to decode tag %q: %v", wt.Tag, err)
	}

	keyLen, msgLen, tagLen := len(key), len(msg), len(tag)

	if keyLen == 0 {
		key = append(key, 0)
	}
	if msgLen == 0 {
		msg = append(msg, 0)
	}
	if tagLen == 0 {
		tag = append(tag, 0)
	}

	mdctx := C.EVP_MD_CTX_new()
	if mdctx == nil {
		log.Fatal("EVP_MD_CTX_new failed")
	}
	defer C.EVP_MD_CTX_free(mdctx)

	pkey := C.EVP_PKEY_new_CMAC_key(nil, (*C.uchar)(unsafe.Pointer(&key[0])), C.size_t(keyLen), cipher)
	if pkey == nil {
		log.Fatal("CMAC_CTX_new failed")
	}
	defer C.EVP_PKEY_free(pkey)

	ret := C.EVP_DigestSignInit(mdctx, nil, nil, nil, pkey)
	if ret != 1 {
		fmt.Printf("FAIL: Test case %d (%q) %v - EVP_DigestSignInit() = %d, want %v\n",
			wt.TCID, wt.Comment, wt.Flags, ret, wt.Result)
		return false
	}

	var outLen C.size_t
	outTag := make([]byte, 16)

	ret = C.EVP_DigestSign(mdctx, (*C.uchar)(unsafe.Pointer(&outTag[0])), &outLen, (*C.uchar)(unsafe.Pointer(&msg[0])), C.size_t(msgLen))
	if ret != 1 {
		fmt.Printf("FAIL: Test case %d (%q) %v - EVP_DigestSign() = %d, want %v\n",
			wt.TCID, wt.Comment, wt.Flags, ret, wt.Result)
		return false
	}

	outTag = outTag[0:tagLen]

	success := true
	if bytes.Equal(tag, outTag) != (wt.Result == "valid") {
		fmt.Printf("FAIL: Test case %d (%q) %v - want %v\n",
			wt.TCID, wt.Comment, wt.Flags, wt.Result)
		success = false
	}
	return success
}

func runAesCmacTestGroup(algorithm string, wtg *wycheproofTestGroupAesCmac) bool {
	fmt.Printf("Running %v test group %v with key size %d and tag size %d...\n",
		algorithm, wtg.Type, wtg.KeySize, wtg.TagSize)
	var cipher *C.EVP_CIPHER

	switch wtg.KeySize {
	case 128:
		cipher = C.EVP_aes_128_cbc()
	case 192:
		cipher = C.EVP_aes_192_cbc()
	case 256:
		cipher = C.EVP_aes_256_cbc()
	default:
		fmt.Printf("INFO: Skipping tests with invalid key size %d\n", wtg.KeySize)
		return true
	}

	success := true
	for _, wt := range wtg.Tests {
		if !runAesCmacTest(cipher, wt) {
			success = false
		}
	}
	return success
}

func checkAeadOpen(ctx *C.EVP_AEAD_CTX, iv []byte, ivLen int, aad []byte, aadLen int, msg []byte, msgLen int,
	ct []byte, ctLen int, tag []byte, tagLen int, wt *wycheproofTestAead) bool {
	maxOutLen := ctLen + tagLen

	opened := make([]byte, maxOutLen)
	if maxOutLen == 0 {
		opened = append(opened, 0)
	}
	var openedMsgLen C.size_t

	catCtTag := append(ct, tag...)
	catCtTagLen := len(catCtTag)
	if catCtTagLen == 0 {
		catCtTag = append(catCtTag, 0)
	}
	openRet := C.EVP_AEAD_CTX_open(ctx, (*C.uint8_t)(unsafe.Pointer(&opened[0])),
		(*C.size_t)(unsafe.Pointer(&openedMsgLen)), C.size_t(maxOutLen),
		(*C.uint8_t)(unsafe.Pointer(&iv[0])), C.size_t(ivLen),
		(*C.uint8_t)(unsafe.Pointer(&catCtTag[0])), C.size_t(catCtTagLen),
		(*C.uint8_t)(unsafe.Pointer(&aad[0])), C.size_t(aadLen))

	if openRet != 1 {
		if wt.Result == "invalid" {
			return true
		}
		fmt.Printf("FAIL: Test case %d (%q) %v - EVP_AEAD_CTX_open() = %d, want %v\n",
			wt.TCID, wt.Comment, wt.Flags, int(openRet), wt.Result)
		return false
	}

	if openedMsgLen != C.size_t(msgLen) {
		fmt.Printf("FAIL: Test case %d (%q) %v - open length mismatch: got %d, want %d\n",
			wt.TCID, wt.Comment, wt.Flags, openedMsgLen, msgLen)
		return false
	}

	openedMsg := opened[0:openedMsgLen]
	if msgLen == 0 {
		msg = nil
	}

	success := false
	if bytes.Equal(openedMsg, msg) == (wt.Result != "invalid") {
		success = true
	} else {
		fmt.Printf("FAIL: Test case %d (%q) %v - msg match: %t; want %v\n",
			wt.TCID, wt.Comment, wt.Flags, bytes.Equal(openedMsg, msg), wt.Result)
	}
	return success
}

func checkAeadSeal(ctx *C.EVP_AEAD_CTX, iv []byte, ivLen int, aad []byte, aadLen int, msg []byte,
	msgLen int, ct []byte, ctLen int, tag []byte, tagLen int, wt *wycheproofTestAead) bool {
	maxOutLen := msgLen + tagLen

	sealed := make([]byte, maxOutLen)
	if maxOutLen == 0 {
		sealed = append(sealed, 0)
	}
	var sealedLen C.size_t

	sealRet := C.EVP_AEAD_CTX_seal(ctx, (*C.uint8_t)(unsafe.Pointer(&sealed[0])),
		(*C.size_t)(unsafe.Pointer(&sealedLen)), C.size_t(maxOutLen),
		(*C.uint8_t)(unsafe.Pointer(&iv[0])), C.size_t(ivLen),
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(msgLen),
		(*C.uint8_t)(unsafe.Pointer(&aad[0])), C.size_t(aadLen))

	if sealRet != 1 {
		success := (wt.Result == "invalid")
		if !success {
			fmt.Printf("FAIL: Test case %d (%q) %v - EVP_AEAD_CTX_seal() = %d, want %v\n", wt.TCID, wt.Comment, wt.Flags, int(sealRet), wt.Result)
		}
		return success
	}

	if sealedLen != C.size_t(maxOutLen) {
		fmt.Printf("FAIL: Test case %d (%q) %v - seal length mismatch: got %d, want %d\n",
			wt.TCID, wt.Comment, wt.Flags, sealedLen, maxOutLen)
		return false
	}

	sealedCt := sealed[0:msgLen]
	sealedTag := sealed[msgLen:maxOutLen]

	success := false
	if (bytes.Equal(sealedCt, ct) && bytes.Equal(sealedTag, tag)) == (wt.Result != "invalid") {
		success = true
	} else {
		fmt.Printf("FAIL: Test case %d (%q) %v - EVP_AEAD_CTX_seal() = %d, ct match: %t, tag match: %t; want %v\n",
			wt.TCID, wt.Comment, wt.Flags, int(sealRet),
			bytes.Equal(sealedCt, ct), bytes.Equal(sealedTag, tag), wt.Result)
	}
	return success
}

func runChaCha20Poly1305Test(algorithm string, wt *wycheproofTestAead) bool {
	var aead *C.EVP_AEAD
	switch algorithm {
	case "CHACHA20-POLY1305":
		aead = C.EVP_aead_chacha20_poly1305()
	case "XCHACHA20-POLY1305":
		aead = C.EVP_aead_xchacha20_poly1305()
	}

	key, err := hex.DecodeString(wt.Key)
	if err != nil {
		log.Fatalf("Failed to decode key %q: %v", wt.Key, err)
	}
	iv, err := hex.DecodeString(wt.IV)
	if err != nil {
		log.Fatalf("Failed to decode key %q: %v", wt.IV, err)
	}
	aad, err := hex.DecodeString(wt.AAD)
	if err != nil {
		log.Fatalf("Failed to decode AAD %q: %v", wt.AAD, err)
	}
	msg, err := hex.DecodeString(wt.Msg)
	if err != nil {
		log.Fatalf("Failed to decode msg %q: %v", wt.Msg, err)
	}
	ct, err := hex.DecodeString(wt.CT)
	if err != nil {
		log.Fatalf("Failed to decode ct %q: %v", wt.CT, err)
	}
	tag, err := hex.DecodeString(wt.Tag)
	if err != nil {
		log.Fatalf("Failed to decode tag %q: %v", wt.Tag, err)
	}

	keyLen, ivLen, aadLen, msgLen, ctLen, tagLen := len(key), len(iv), len(aad), len(msg), len(ct), len(tag)

	if ivLen == 0 {
		iv = append(iv, 0)
	}
	if aadLen == 0 {
		aad = append(aad, 0)
	}
	if msgLen == 0 {
		msg = append(msg, 0)
	}

	ctx := C.EVP_AEAD_CTX_new()
	if ctx == nil {
		log.Fatal("EVP_AEAD_CTX_new() failed")
	}
	defer C.EVP_AEAD_CTX_free(ctx)
	if C.EVP_AEAD_CTX_init(ctx, aead, (*C.uchar)(unsafe.Pointer(&key[0])), C.size_t(keyLen), C.size_t(tagLen), nil) != 1 {
		log.Fatal("Failed to initialize AEAD context")
	}

	openSuccess := checkAeadOpen(ctx, iv, ivLen, aad, aadLen, msg, msgLen, ct, ctLen, tag, tagLen, wt)
	sealSuccess := checkAeadSeal(ctx, iv, ivLen, aad, aadLen, msg, msgLen, ct, ctLen, tag, tagLen, wt)

	return openSuccess && sealSuccess
}

func runChaCha20Poly1305TestGroup(algorithm string, wtg *wycheproofTestGroupAead) bool {
	// ChaCha20-Poly1305 currently only supports nonces of length 12 (96 bits)
	if algorithm == "CHACHA20-POLY1305" && wtg.IVSize != 96 {
		return true
	}

	fmt.Printf("Running %v test group %v with IV size %d, key size %d, tag size %d...\n",
		algorithm, wtg.Type, wtg.IVSize, wtg.KeySize, wtg.TagSize)

	success := true
	for _, wt := range wtg.Tests {
		if !runChaCha20Poly1305Test(algorithm, wt) {
			success = false
		}
	}
	return success
}

// DER encode the signature (so DSA_verify() can decode and encode it again)
func encodeDSAP1363Sig(wtSig string) (*C.uchar, C.int) {
	cSig := C.DSA_SIG_new()
	if cSig == nil {
		log.Fatal("DSA_SIG_new() failed")
	}
	defer C.DSA_SIG_free(cSig)

	sigLen := len(wtSig)
	r := C.CString(wtSig[:sigLen/2])
	s := C.CString(wtSig[sigLen/2:])
	defer C.free(unsafe.Pointer(r))
	defer C.free(unsafe.Pointer(s))
	var sigR *C.BIGNUM
	var sigS *C.BIGNUM
	defer C.BN_free(sigR)
	defer C.BN_free(sigS)
	if C.BN_hex2bn(&sigR, r) == 0 {
		return nil, 0
	}
	if C.BN_hex2bn(&sigS, s) == 0 {
		return nil, 0
	}
	if C.DSA_SIG_set0(cSig, sigR, sigS) == 0 {
		return nil, 0
	}
	sigR = nil
	sigS = nil

	derLen := C.i2d_DSA_SIG(cSig, nil)
	if derLen == 0 {
		return nil, 0
	}
	cDer := (*C.uchar)(C.malloc(C.ulong(derLen)))
	if cDer == nil {
		log.Fatal("malloc failed")
	}

	p := cDer
	ret := C.i2d_DSA_SIG(cSig, (**C.uchar)(&p))
	if ret == 0 || ret != derLen {
		C.free(unsafe.Pointer(cDer))
		return nil, 0
	}

	return cDer, derLen
}

func runDSATest(dsa *C.DSA, md *C.EVP_MD, variant testVariant, wt *wycheproofTestDSA) bool {
	msg, err := hex.DecodeString(wt.Msg)
	if err != nil {
		log.Fatalf("Failed to decode message %q: %v", wt.Msg, err)
	}

	msg, msgLen, err := hashEvpDigestMessage(md, msg)
	if err != nil {
		log.Fatalf("%v", err)
	}

	var ret C.int
	if variant == P1363 {
		cDer, derLen := encodeDSAP1363Sig(wt.Sig)
		if cDer == nil {
			fmt.Print("FAIL: unable to decode signature")
			return false
		}
		defer C.free(unsafe.Pointer(cDer))

		ret = C.DSA_verify(0, (*C.uchar)(unsafe.Pointer(&msg[0])), C.int(msgLen),
			(*C.uchar)(unsafe.Pointer(cDer)), C.int(derLen), dsa)
	} else {
		sig, err := hex.DecodeString(wt.Sig)
		if err != nil {
			log.Fatalf("Failed to decode signature %q: %v", wt.Sig, err)
		}
		sigLen := len(sig)
		if sigLen == 0 {
			sig = append(msg, 0)
		}
		ret = C.DSA_verify(0, (*C.uchar)(unsafe.Pointer(&msg[0])), C.int(msgLen),
			(*C.uchar)(unsafe.Pointer(&sig[0])), C.int(sigLen), dsa)
	}

	success := true
	if ret == 1 != (wt.Result == "valid") {
		fmt.Printf("FAIL: Test case %d (%q) %v - DSA_verify() = %d, want %v\n",
			wt.TCID, wt.Comment, wt.Flags, ret, wt.Result)
		success = false
	}
	return success
}

func runDSATestGroup(algorithm string, variant testVariant, wtg *wycheproofTestGroupDSA) bool {
	fmt.Printf("Running %v test group %v, key size %d and %v...\n",
		algorithm, wtg.Type, wtg.Key.KeySize, wtg.SHA)

	dsa := C.DSA_new()
	if dsa == nil {
		log.Fatal("DSA_new failed")
	}
	defer C.DSA_free(dsa)

	var bnG *C.BIGNUM
	wg := C.CString(wtg.Key.G)
	if C.BN_hex2bn(&bnG, wg) == 0 {
		log.Fatal("Failed to decode g")
	}
	C.free(unsafe.Pointer(wg))

	var bnP *C.BIGNUM
	wp := C.CString(wtg.Key.P)
	if C.BN_hex2bn(&bnP, wp) == 0 {
		log.Fatal("Failed to decode p")
	}
	C.free(unsafe.Pointer(wp))

	var bnQ *C.BIGNUM
	wq := C.CString(wtg.Key.Q)
	if C.BN_hex2bn(&bnQ, wq) == 0 {
		log.Fatal("Failed to decode q")
	}
	C.free(unsafe.Pointer(wq))

	ret := C.DSA_set0_pqg(dsa, bnP, bnQ, bnG)
	if ret != 1 {
		log.Fatalf("DSA_set0_pqg returned %d", ret)
	}

	var bnY *C.BIGNUM
	wy := C.CString(wtg.Key.Y)
	if C.BN_hex2bn(&bnY, wy) == 0 {
		log.Fatal("Failed to decode y")
	}
	C.free(unsafe.Pointer(wy))

	ret = C.DSA_set0_key(dsa, bnY, nil)
	if ret != 1 {
		log.Fatalf("DSA_set0_key returned %d", ret)
	}

	md, err := hashEvpMdFromString(wtg.SHA)
	if err != nil {
		log.Fatalf("Failed to get hash: %v", err)
	}

	der, err := hex.DecodeString(wtg.KeyDER)
	if err != nil {
		log.Fatalf("Failed to decode DER encoded key: %v", err)
	}

	derLen := len(der)
	if derLen == 0 {
		der = append(der, 0)
	}

	Cder := (*C.uchar)(C.malloc(C.ulong(derLen)))
	if Cder == nil {
		log.Fatal("malloc failed")
	}
	C.memcpy(unsafe.Pointer(Cder), unsafe.Pointer(&der[0]), C.ulong(derLen))

	p := (*C.uchar)(Cder)
	dsaDER := C.d2i_DSA_PUBKEY(nil, (**C.uchar)(&p), C.long(derLen))
	defer C.DSA_free(dsaDER)
	C.free(unsafe.Pointer(Cder))

	keyPEM := C.CString(wtg.KeyPEM)
	bio := C.BIO_new_mem_buf(unsafe.Pointer(keyPEM), C.int(len(wtg.KeyPEM)))
	if bio == nil {
		log.Fatal("BIO_new_mem_buf failed")
	}
	defer C.free(unsafe.Pointer(keyPEM))
	defer C.BIO_free(bio)

	dsaPEM := C.PEM_read_bio_DSA_PUBKEY(bio, nil, nil, nil)
	if dsaPEM == nil {
		log.Fatal("PEM_read_bio_DSA_PUBKEY failed")
	}
	defer C.DSA_free(dsaPEM)

	success := true
	for _, wt := range wtg.Tests {
		if !runDSATest(dsa, md, variant, wt) {
			success = false
		}
		if !runDSATest(dsaDER, md, variant, wt) {
			success = false
		}
		if !runDSATest(dsaPEM, md, variant, wt) {
			success = false
		}
	}
	return success
}

func runECDHTest(nid int, variant testVariant, wt *wycheproofTestECDH) bool {
	privKey := C.EC_KEY_new_by_curve_name(C.int(nid))
	if privKey == nil {
		log.Fatalf("EC_KEY_new_by_curve_name failed")
	}
	defer C.EC_KEY_free(privKey)

	var bnPriv *C.BIGNUM
	wPriv := C.CString(wt.Private)
	if C.BN_hex2bn(&bnPriv, wPriv) == 0 {
		log.Fatal("Failed to decode wPriv")
	}
	C.free(unsafe.Pointer(wPriv))
	defer C.BN_free(bnPriv)

	ret := C.EC_KEY_set_private_key(privKey, bnPriv)
	if ret != 1 {
		fmt.Printf("FAIL: Test case %d (%q) %v - EC_KEY_set_private_key() = %d, want %v\n",
			wt.TCID, wt.Comment, wt.Flags, ret, wt.Result)
		return false
	}

	pub, err := hex.DecodeString(wt.Public)
	if err != nil {
		log.Fatalf("Failed to decode public key: %v", err)
	}

	pubLen := len(pub)
	if pubLen == 0 {
		pub = append(pub, 0)
	}

	Cpub := (*C.uchar)(C.malloc(C.ulong(pubLen)))
	if Cpub == nil {
		log.Fatal("malloc failed")
	}
	C.memcpy(unsafe.Pointer(Cpub), unsafe.Pointer(&pub[0]), C.ulong(pubLen))

	p := (*C.uchar)(Cpub)
	var pubKey *C.EC_KEY
	if variant == EcPoint {
		pubKey = C.EC_KEY_new_by_curve_name(C.int(nid))
		if pubKey == nil {
			log.Fatal("EC_KEY_new_by_curve_name failed")
		}
		pubKey = C.o2i_ECPublicKey(&pubKey, (**C.uchar)(&p), C.long(pubLen))
	} else {
		pubKey = C.d2i_EC_PUBKEY(nil, (**C.uchar)(&p), C.long(pubLen))
	}
	defer C.EC_KEY_free(pubKey)
	C.free(unsafe.Pointer(Cpub))

	if pubKey == nil {
		if wt.Result == "invalid" || wt.Result == "acceptable" {
			return true
		}
		fmt.Printf("FAIL: Test case %d (%q) %v - ASN decoding failed: want %v\n",
			wt.TCID, wt.Comment, wt.Flags, wt.Result)
		return false
	}

	privGroup := C.EC_KEY_get0_group(privKey)

	secLen := (C.EC_GROUP_get_degree(privGroup) + 7) / 8

	secret := make([]byte, secLen)
	if secLen == 0 {
		secret = append(secret, 0)
	}

	pubPoint := C.EC_KEY_get0_public_key(pubKey)

	ret = C.ECDH_compute_key(unsafe.Pointer(&secret[0]), C.ulong(secLen), pubPoint, privKey, nil)
	if ret != C.int(secLen) {
		if wt.Result == "invalid" {
			return true
		}
		fmt.Printf("FAIL: Test case %d (%q) %v - ECDH_compute_key() = %d, want %d, result: %v\n",
			wt.TCID, wt.Comment, wt.Flags, ret, int(secLen), wt.Result)
		return false
	}

	shared, err := hex.DecodeString(wt.Shared)
	if err != nil {
		log.Fatalf("Failed to decode shared secret: %v", err)
	}

	// XXX The shared fields of the secp224k1 test cases have a 0 byte preprended.
	if len(shared) == int(secLen)+1 && shared[0] == 0 {
		fmt.Printf("INFO: Test case %d (%q) %v - prepending 0 byte\n", wt.TCID, wt.Comment, wt.Flags)
		// shared = shared[1:];
		zero := make([]byte, 1, secLen+1)
		secret = append(zero, secret...)
	}

	success := true
	if !bytes.Equal(shared, secret) {
		fmt.Printf("FAIL: Test case %d (%q) %v - expected and computed shared secret do not match, want %v\n",
			wt.TCID, wt.Comment, wt.Flags, wt.Result)
		success = false
	}
	return success
}

func runECDHTestGroup(algorithm string, variant testVariant, wtg *wycheproofTestGroupECDH) bool {
	fmt.Printf("Running %v test group %v with curve %v and %v encoding...\n",
		algorithm, wtg.Type, wtg.Curve, wtg.Encoding)

	nid, err := nidFromString(wtg.Curve)
	if err != nil {
		log.Fatalf("Failed to get nid for curve: %v", err)
	}

	success := true
	for _, wt := range wtg.Tests {
		if !runECDHTest(nid, variant, wt) {
			success = false
		}
	}
	return success
}

func runECDHWebCryptoTest(nid int, wt *wycheproofTestECDHWebCrypto) bool {
	privKey := C.EC_KEY_new_by_curve_name(C.int(nid))
	if privKey == nil {
		log.Fatalf("EC_KEY_new_by_curve_name failed")
	}
	defer C.EC_KEY_free(privKey)

	d, err := base64.RawURLEncoding.DecodeString(wt.Private.D)
	if err != nil {
		log.Fatalf("Failed to base64 decode d: %v", err)
	}
	bnD := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&d[0])), C.int(len(d)), nil)
	if bnD == nil {
		log.Fatal("Failed to decode D")
	}
	defer C.BN_free(bnD)

	ret := C.EC_KEY_set_private_key(privKey, bnD)
	if ret != 1 {
		fmt.Printf("FAIL: Test case %d (%q) %v - EC_KEY_set_private_key() = %d, want %v\n",
			wt.TCID, wt.Comment, wt.Flags, ret, wt.Result)
		return false
	}

	x, err := base64.RawURLEncoding.DecodeString(wt.Public.X)
	if err != nil {
		log.Fatalf("Failed to base64 decode x: %v", err)
	}
	bnX := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&x[0])), C.int(len(x)), nil)
	if bnX == nil {
		log.Fatal("Failed to decode X")
	}
	defer C.BN_free(bnX)

	y, err := base64.RawURLEncoding.DecodeString(wt.Public.Y)
	if err != nil {
		log.Fatalf("Failed to base64 decode y: %v", err)
	}
	bnY := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&y[0])), C.int(len(y)), nil)
	if bnY == nil {
		log.Fatal("Failed to decode Y")
	}
	defer C.BN_free(bnY)

	pubKey := C.EC_KEY_new_by_curve_name(C.int(nid))
	if pubKey == nil {
		log.Fatal("Failed to create EC_KEY")
	}
	defer C.EC_KEY_free(pubKey)

	ret = C.EC_KEY_set_public_key_affine_coordinates(pubKey, bnX, bnY)
	if ret != 1 {
		if wt.Result == "invalid" {
			return true
		}
		fmt.Printf("FAIL: Test case %d (%q) %v - EC_KEY_set_public_key_affine_coordinates() = %d, want %v\n",
			wt.TCID, wt.Comment, wt.Flags, ret, wt.Result)
		return false
	}
	pubPoint := C.EC_KEY_get0_public_key(pubKey)

	privGroup := C.EC_KEY_get0_group(privKey)

	secLen := (C.EC_GROUP_get_degree(privGroup) + 7) / 8

	secret := make([]byte, secLen)
	if secLen == 0 {
		secret = append(secret, 0)
	}

	ret = C.ECDH_compute_key(unsafe.Pointer(&secret[0]), C.ulong(secLen), pubPoint, privKey, nil)
	if ret != C.int(secLen) {
		if wt.Result == "invalid" {
			return true
		}
		fmt.Printf("FAIL: Test case %d (%q) %v - ECDH_compute_key() = %d, want %d, result: %v\n",
			wt.TCID, wt.Comment, wt.Flags, ret, int(secLen), wt.Result)
		return false
	}

	shared, err := hex.DecodeString(wt.Shared)
	if err != nil {
		log.Fatalf("Failed to decode shared secret: %v", err)
	}

	success := true
	if !bytes.Equal(shared, secret) {
		fmt.Printf("FAIL: Test case %d (%q) %v - expected and computed shared secret do not match, want %v\n",
			wt.TCID, wt.Comment, wt.Flags, wt.Result)
		success = false
	}
	return success
}

func runECDHWebCryptoTestGroup(algorithm string, wtg *wycheproofTestGroupECDHWebCrypto) bool {
	fmt.Printf("Running %v test group %v with curve %v and %v encoding...\n",
		algorithm, wtg.Type, wtg.Curve, wtg.Encoding)

	nid, err := nidFromString(wtg.Curve)
	if err != nil {
		log.Fatalf("Failed to get nid for curve: %v", err)
	}

	success := true
	for _, wt := range wtg.Tests {
		if !runECDHWebCryptoTest(nid, wt) {
			success = false
		}
	}
	return success
}

func runECDSATest(ecKey *C.EC_KEY, md *C.EVP_MD, nid int, variant testVariant, wt *wycheproofTestECDSA) bool {
	msg, err := hex.DecodeString(wt.Msg)
	if err != nil {
		log.Fatalf("Failed to decode message %q: %v", wt.Msg, err)
	}

	msg, msgLen, err := hashEvpDigestMessage(md, msg)
	if err != nil {
		log.Fatalf("%v", err)
	}

	var ret C.int
	if variant == Webcrypto || variant == P1363 {
		cDer, derLen := encodeECDSAWebCryptoSig(wt.Sig)
		if cDer == nil {
			fmt.Print("FAIL: unable to decode signature")
			return false
		}
		defer C.free(unsafe.Pointer(cDer))

		ret = C.ECDSA_verify(0, (*C.uchar)(unsafe.Pointer(&msg[0])), C.int(msgLen),
			(*C.uchar)(unsafe.Pointer(cDer)), C.int(derLen), ecKey)
	} else {
		sig, err := hex.DecodeString(wt.Sig)
		if err != nil {
			log.Fatalf("Failed to decode signature %q: %v", wt.Sig, err)
		}

		sigLen := len(sig)
		if sigLen == 0 {
			sig = append(sig, 0)
		}
		ret = C.ECDSA_verify(0, (*C.uchar)(unsafe.Pointer(&msg[0])), C.int(msgLen),
			(*C.uchar)(unsafe.Pointer(&sig[0])), C.int(sigLen), ecKey)
	}

	// XXX audit acceptable cases...
	success := true
	if ret == 1 != (wt.Result == "valid") && wt.Result != "acceptable" {
		fmt.Printf("FAIL: Test case %d (%q) %v - ECDSA_verify() = %d, want %v\n",
			wt.TCID, wt.Comment, wt.Flags, int(ret), wt.Result)
		success = false
	}
	return success
}

func runECDSATestGroup(algorithm string, variant testVariant, wtg *wycheproofTestGroupECDSA) bool {
	fmt.Printf("Running %v test group %v with curve %v, key size %d and %v...\n",
		algorithm, wtg.Type, wtg.Key.Curve, wtg.Key.KeySize, wtg.SHA)

	nid, err := nidFromString(wtg.Key.Curve)
	if err != nil {
		log.Fatalf("Failed to get nid for curve: %v", err)
	}
	ecKey := C.EC_KEY_new_by_curve_name(C.int(nid))
	if ecKey == nil {
		log.Fatal("EC_KEY_new_by_curve_name failed")
	}
	defer C.EC_KEY_free(ecKey)

	var bnX *C.BIGNUM
	wx := C.CString(wtg.Key.WX)
	if C.BN_hex2bn(&bnX, wx) == 0 {
		log.Fatal("Failed to decode WX")
	}
	C.free(unsafe.Pointer(wx))
	defer C.BN_free(bnX)

	var bnY *C.BIGNUM
	wy := C.CString(wtg.Key.WY)
	if C.BN_hex2bn(&bnY, wy) == 0 {
		log.Fatal("Failed to decode WY")
	}
	C.free(unsafe.Pointer(wy))
	defer C.BN_free(bnY)

	if C.EC_KEY_set_public_key_affine_coordinates(ecKey, bnX, bnY) != 1 {
		log.Fatal("Failed to set EC public key")
	}

	nid, err = nidFromString(wtg.SHA)
	if err != nil {
		log.Fatalf("Failed to get MD NID: %v", err)
	}
	md, err := hashEvpMdFromString(wtg.SHA)
	if err != nil {
		log.Fatalf("Failed to get hash: %v", err)
	}

	success := true
	for _, wt := range wtg.Tests {
		if !runECDSATest(ecKey, md, nid, variant, wt) {
			success = false
		}
	}
	return success
}

// DER encode the signature (so that ECDSA_verify() can decode and encode it again...)
func encodeECDSAWebCryptoSig(wtSig string) (*C.uchar, C.int) {
	cSig := C.ECDSA_SIG_new()
	if cSig == nil {
		log.Fatal("ECDSA_SIG_new() failed")
	}
	defer C.ECDSA_SIG_free(cSig)

	sigLen := len(wtSig)
	r := C.CString(wtSig[:sigLen/2])
	s := C.CString(wtSig[sigLen/2:])
	defer C.free(unsafe.Pointer(r))
	defer C.free(unsafe.Pointer(s))
	var sigR *C.BIGNUM
	var sigS *C.BIGNUM
	defer C.BN_free(sigR)
	defer C.BN_free(sigS)
	if C.BN_hex2bn(&sigR, r) == 0 {
		return nil, 0
	}
	if C.BN_hex2bn(&sigS, s) == 0 {
		return nil, 0
	}
	if C.ECDSA_SIG_set0(cSig, sigR, sigS) == 0 {
		return nil, 0
	}
	sigR = nil
	sigS = nil

	derLen := C.i2d_ECDSA_SIG(cSig, nil)
	if derLen == 0 {
		return nil, 0
	}
	cDer := (*C.uchar)(C.malloc(C.ulong(derLen)))
	if cDer == nil {
		log.Fatal("malloc failed")
	}

	p := cDer
	ret := C.i2d_ECDSA_SIG(cSig, (**C.uchar)(&p))
	if ret == 0 || ret != derLen {
		C.free(unsafe.Pointer(cDer))
		return nil, 0
	}

	return cDer, derLen
}

func runECDSAWebCryptoTestGroup(algorithm string, wtg *wycheproofTestGroupECDSAWebCrypto) bool {
	fmt.Printf("Running %v test group %v with curve %v, key size %d and %v...\n",
		algorithm, wtg.Type, wtg.Key.Curve, wtg.Key.KeySize, wtg.SHA)

	nid, err := nidFromString(wtg.JWK.Crv)
	if err != nil {
		log.Fatalf("Failed to get nid for curve: %v", err)
	}
	ecKey := C.EC_KEY_new_by_curve_name(C.int(nid))
	if ecKey == nil {
		log.Fatal("EC_KEY_new_by_curve_name failed")
	}
	defer C.EC_KEY_free(ecKey)

	x, err := base64.RawURLEncoding.DecodeString(wtg.JWK.X)
	if err != nil {
		log.Fatalf("Failed to base64 decode X: %v", err)
	}
	bnX := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&x[0])), C.int(len(x)), nil)
	if bnX == nil {
		log.Fatal("Failed to decode X")
	}
	defer C.BN_free(bnX)

	y, err := base64.RawURLEncoding.DecodeString(wtg.JWK.Y)
	if err != nil {
		log.Fatalf("Failed to base64 decode Y: %v", err)
	}
	bnY := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&y[0])), C.int(len(y)), nil)
	if bnY == nil {
		log.Fatal("Failed to decode Y")
	}
	defer C.BN_free(bnY)

	if C.EC_KEY_set_public_key_affine_coordinates(ecKey, bnX, bnY) != 1 {
		log.Fatal("Failed to set EC public key")
	}

	nid, err = nidFromString(wtg.SHA)
	if err != nil {
		log.Fatalf("Failed to get MD NID: %v", err)
	}
	md, err := hashEvpMdFromString(wtg.SHA)
	if err != nil {
		log.Fatalf("Failed to get hash: %v", err)
	}

	success := true
	for _, wt := range wtg.Tests {
		if !runECDSATest(ecKey, md, nid, Webcrypto, wt) {
			success = false
		}
	}
	return success
}

func runEdDSATest(pkey *C.EVP_PKEY, wt *wycheproofTestEdDSA) bool {
	mdctx := C.EVP_MD_CTX_new()
	if mdctx == nil {
		log.Fatal("EVP_MD_CTX_new failed")
	}
	defer C.EVP_MD_CTX_free(mdctx)

	if C.EVP_DigestVerifyInit(mdctx, nil, nil, nil, pkey) != 1 {
		log.Fatal("EVP_DigestVerifyInit failed")
	}

	msg, err := hex.DecodeString(wt.Msg)
	if err != nil {
		log.Fatalf("Failed to decode Message %q: %v", wt.Msg, err)
	}
	msgLen := len(msg)
	if msgLen == 0 {
		msg = append(msg, 0)
	}

	sig, err := hex.DecodeString(wt.Sig)
	if err != nil {
		log.Fatalf("Failed to decode Signature %q: %v", wt.Sig, err)
	}
	sigLen := len(sig)
	if sigLen == 0 {
		sig = append(sig, 0)
	}

	ret := C.EVP_DigestVerify(mdctx, (*C.uchar)(unsafe.Pointer(&sig[0])), (C.size_t)(sigLen), (*C.uchar)(unsafe.Pointer(&msg[0])), (C.size_t)(msgLen))

	success := true
	if (ret == 1) != (wt.Result == "valid") {
		fmt.Printf("FAIL: Test case %d (%q) %v - EVP_DigestVerify() = %d, want %v\n",
			wt.TCID, wt.Comment, wt.Flags, int(ret), wt.Result)
		success = false
	}
	return success
}

func runEdDSATestGroup(algorithm string, wtg *wycheproofTestGroupEdDSA) bool {
	fmt.Printf("Running %v test group %v...\n", algorithm, wtg.Type)

	if wtg.Key.Curve != "edwards25519" || wtg.Key.KeySize != 255 {
		fmt.Printf("INFO: Unexpected curve or key size. want (\"edwards25519\", 255), got (%q, %d)\n", wtg.Key.Curve, wtg.Key.KeySize)
		return false
	}

	pubKey, err := hex.DecodeString(wtg.Key.Pk)
	if err != nil {
		log.Fatalf("Failed to decode Pubkey %q: %v", wtg.Key.Pk, err)
	}

	pkey := C.EVP_PKEY_new_raw_public_key(C.EVP_PKEY_ED25519, nil, (*C.uchar)(unsafe.Pointer(&pubKey[0])), (C.size_t)(len(pubKey)))
	if pkey == nil {
		log.Fatal("EVP_PKEY_new_raw_public_key failed")
	}
	defer C.EVP_PKEY_free(pkey)

	success := true
	for _, wt := range wtg.Tests {
		if !runEdDSATest(pkey, wt) {
			success = false
		}
	}
	return success
}

func runHkdfTest(md *C.EVP_MD, wt *wycheproofTestHkdf) bool {
	ikm, err := hex.DecodeString(wt.Ikm)
	if err != nil {
		log.Fatalf("Failed to decode ikm %q: %v", wt.Ikm, err)
	}
	salt, err := hex.DecodeString(wt.Salt)
	if err != nil {
		log.Fatalf("Failed to decode salt %q: %v", wt.Salt, err)
	}
	info, err := hex.DecodeString(wt.Info)
	if err != nil {
		log.Fatalf("Failed to decode info %q: %v", wt.Info, err)
	}

	ikmLen, saltLen, infoLen := len(ikm), len(salt), len(info)
	if ikmLen == 0 {
		ikm = append(ikm, 0)
	}
	if saltLen == 0 {
		salt = append(salt, 0)
	}
	if infoLen == 0 {
		info = append(info, 0)
	}

	outLen := wt.Size
	out := make([]byte, outLen)
	if outLen == 0 {
		out = append(out, 0)
	}

	pctx := C.EVP_PKEY_CTX_new_id(C.EVP_PKEY_HKDF, nil)
	if pctx == nil {
		log.Fatalf("EVP_PKEY_CTX_new_id failed")
	}
	defer C.EVP_PKEY_CTX_free(pctx)

	ret := C.EVP_PKEY_derive_init(pctx)
	if ret <= 0 {
		log.Fatalf("EVP_PKEY_derive_init failed, want 1, got %d", ret)
	}

	ret = C.wp_EVP_PKEY_CTX_set_hkdf_md(pctx, md)
	if ret <= 0 {
		log.Fatalf("EVP_PKEY_CTX_set_hkdf_md failed, want 1, got %d", ret)
	}

	ret = C.wp_EVP_PKEY_CTX_set1_hkdf_salt(pctx, (*C.uchar)(&salt[0]), C.size_t(saltLen))
	if ret <= 0 {
		log.Fatalf("EVP_PKEY_CTX_set1_hkdf_salt failed, want 1, got %d", ret)
	}

	ret = C.wp_EVP_PKEY_CTX_set1_hkdf_key(pctx, (*C.uchar)(&ikm[0]), C.size_t(ikmLen))
	if ret <= 0 {
		log.Fatalf("EVP_PKEY_CTX_set1_hkdf_key failed, want 1, got %d", ret)
	}

	ret = C.wp_EVP_PKEY_CTX_add1_hkdf_info(pctx, (*C.uchar)(&info[0]), C.size_t(infoLen))
	if ret <= 0 {
		log.Fatalf("EVP_PKEY_CTX_add1_hkdf_info failed, want 1, got %d", ret)
	}

	ret = C.EVP_PKEY_derive(pctx, (*C.uchar)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(&outLen)))
	if ret <= 0 {
		success := wt.Result == "invalid"
		if !success {
			fmt.Printf("FAIL: Test case %d (%q) %v - got %d, want %v\n", wt.TCID, wt.Comment, wt.Flags, ret, wt.Result)
		}
		return success
	}

	okm, err := hex.DecodeString(wt.Okm)
	if err != nil {
		log.Fatalf("Failed to decode okm %q: %v", wt.Okm, err)
	}
	if !bytes.Equal(out[:outLen], okm) {
		fmt.Printf("FAIL: Test case %d (%q) %v - expected and computed output don't match: %v\n", wt.TCID, wt.Comment, wt.Flags, wt.Result)
	}

	return wt.Result == "valid"
}

func runHkdfTestGroup(algorithm string, wtg *wycheproofTestGroupHkdf) bool {
	fmt.Printf("Running %v test group %v with key size %d...\n", algorithm, wtg.Type, wtg.KeySize)
	md, err := hashEvpMdFromString(strings.TrimPrefix(algorithm, "HKDF-"))
	if err != nil {
		log.Fatalf("Failed to get hash: %v", err)
	}

	success := true
	for _, wt := range wtg.Tests {
		if !runHkdfTest(md, wt) {
			success = false
		}
	}
	return success
}

func runHmacTest(md *C.EVP_MD, tagBytes int, wt *wycheproofTestHmac) bool {
	key, err := hex.DecodeString(wt.Key)
	if err != nil {
		log.Fatalf("failed to decode key %q: %v", wt.Key, err)
	}

	msg, err := hex.DecodeString(wt.Msg)
	if err != nil {
		log.Fatalf("failed to decode msg %q: %v", wt.Msg, err)
	}

	keyLen, msgLen := len(key), len(msg)

	if keyLen == 0 {
		key = append(key, 0)
	}

	if msgLen == 0 {
		msg = append(msg, 0)
	}

	got := make([]byte, C.EVP_MAX_MD_SIZE)
	var gotLen C.uint

	ret := C.HMAC(md, unsafe.Pointer(&key[0]), C.int(keyLen), (*C.uchar)(unsafe.Pointer(&msg[0])), C.size_t(msgLen), (*C.uchar)(unsafe.Pointer(&got[0])), &gotLen)

	success := true
	if ret == nil {
		if wt.Result != "invalid" {
			success = false
			fmt.Printf("FAIL: Test case %d (%q) %v - HMAC: got nil, want %v\n", wt.TCID, wt.Comment, wt.Flags, wt.Result)
		}
		return success
	}

	if int(gotLen) < tagBytes {
		fmt.Printf("FAIL: Test case %d (%q) %v - HMAC length: got %d, want %d, expected %v\n", wt.TCID, wt.Comment, wt.Flags, gotLen, tagBytes, wt.Result)
		return false
	}

	tag, err := hex.DecodeString(wt.Tag)
	if err != nil {
		log.Fatalf("failed to decode tag %q: %v", wt.Tag, err)
	}

	success = bytes.Equal(got[:tagBytes], tag) == (wt.Result == "valid")

	if !success {
		fmt.Printf("FAIL: Test case %d (%q) %v - got %v want %v\n", wt.TCID, wt.Comment, wt.Flags, success, wt.Result)
	}

	return success
}

func runHmacTestGroup(algorithm string, wtg *wycheproofTestGroupHmac) bool {
	fmt.Printf("Running %v test group %v with key size %d and tag size %d...\n", algorithm, wtg.Type, wtg.KeySize, wtg.TagSize)
	prefix := "SHA-"
	if strings.HasPrefix(algorithm, "HMACSHA3-") {
		prefix = "SHA"
	}
	md, err := hashEvpMdFromString(prefix + strings.TrimPrefix(algorithm, "HMACSHA"))
	if err != nil {
		log.Fatalf("Failed to get hash: %v", err)
	}

	success := true
	for _, wt := range wtg.Tests {
		if !runHmacTest(md, wtg.TagSize/8, wt) {
			success = false
		}
	}
	return success
}

func runKWTestWrap(keySize int, key []byte, keyLen int, msg []byte, msgLen int, ct []byte, ctLen int, wt *wycheproofTestKW) bool {
	var aesKey C.AES_KEY

	ret := C.AES_set_encrypt_key((*C.uchar)(unsafe.Pointer(&key[0])), (C.int)(keySize), (*C.AES_KEY)(unsafe.Pointer(&aesKey)))
	if ret != 0 {
		fmt.Printf("FAIL: Test case %d (%q) %v - AES_set_encrypt_key() = %d, want %v\n",
			wt.TCID, wt.Comment, wt.Flags, int(ret), wt.Result)
		return false
	}

	outLen := msgLen
	out := make([]byte, outLen)
	copy(out, msg)
	out = append(out, make([]byte, 8)...)
	ret = C.AES_wrap_key((*C.AES_KEY)(unsafe.Pointer(&aesKey)), nil, (*C.uchar)(unsafe.Pointer(&out[0])), (*C.uchar)(unsafe.Pointer(&out[0])), (C.uint)(msgLen))
	success := false
	if ret == C.int(len(out)) && bytes.Equal(out, ct) {
		if wt.Result != "invalid" {
			success = true
		}
	} else if wt.Result != "valid" {
		success = true
	}
	if !success {
		fmt.Printf("FAIL: Test case %d (%q) %v - msgLen = %d, AES_wrap_key() = %d, want %v\n",
			wt.TCID, wt.Comment, wt.Flags, msgLen, int(ret), wt.Result)
	}
	return success
}

func runKWTestUnWrap(keySize int, key []byte, keyLen int, msg []byte, msgLen int, ct []byte, ctLen int, wt *wycheproofTestKW) bool {
	var aesKey C.AES_KEY

	ret := C.AES_set_decrypt_key((*C.uchar)(unsafe.Pointer(&key[0])), (C.int)(keySize), (*C.AES_KEY)(unsafe.Pointer(&aesKey)))
	if ret != 0 {
		fmt.Printf("FAIL: Test case %d (%q) %v - AES_set_encrypt_key() = %d, want %v\n",
			wt.TCID, wt.Comment, wt.Flags, int(ret), wt.Result)
		return false
	}

	out := make([]byte, ctLen)
	copy(out, ct)
	if ctLen == 0 {
		out = append(out, 0)
	}
	ret = C.AES_unwrap_key((*C.AES_KEY)(unsafe.Pointer(&aesKey)), nil, (*C.uchar)(unsafe.Pointer(&out[0])), (*C.uchar)(unsafe.Pointer(&out[0])), (C.uint)(ctLen))
	success := false
	if ret == C.int(ctLen-8) && bytes.Equal(out[0:ret], msg[0:ret]) {
		if wt.Result != "invalid" {
			success = true
		}
	} else if wt.Result != "valid" {
		success = true
	}
	if !success {
		fmt.Printf("FAIL: Test case %d (%q) %v - keyLen = %d, AES_unwrap_key() = %d, want %v\n",
			wt.TCID, wt.Comment, wt.Flags, keyLen, int(ret), wt.Result)
	}
	return success
}

func runKWTest(keySize int, wt *wycheproofTestKW) bool {
	key, err := hex.DecodeString(wt.Key)
	if err != nil {
		log.Fatalf("Failed to decode key %q: %v", wt.Key, err)
	}
	msg, err := hex.DecodeString(wt.Msg)
	if err != nil {
		log.Fatalf("Failed to decode msg %q: %v", wt.Msg, err)
	}
	ct, err := hex.DecodeString(wt.CT)
	if err != nil {
		log.Fatalf("Failed to decode ct %q: %v", wt.CT, err)
	}

	keyLen, msgLen, ctLen := len(key), len(msg), len(ct)

	if keyLen == 0 {
		key = append(key, 0)
	}
	if msgLen == 0 {
		msg = append(msg, 0)
	}
	if ctLen == 0 {
		ct = append(ct, 0)
	}

	wrapSuccess := runKWTestWrap(keySize, key, keyLen, msg, msgLen, ct, ctLen, wt)
	unwrapSuccess := runKWTestUnWrap(keySize, key, keyLen, msg, msgLen, ct, ctLen, wt)

	return wrapSuccess && unwrapSuccess
}

func runKWTestGroup(algorithm string, wtg *wycheproofTestGroupKW) bool {
	fmt.Printf("Running %v test group %v with key size %d...\n",
		algorithm, wtg.Type, wtg.KeySize)

	success := true
	for _, wt := range wtg.Tests {
		if !runKWTest(wtg.KeySize, wt) {
			success = false
		}
	}
	return success
}

func runPrimalityTest(wt *wycheproofTestPrimality) bool {
	var bnValue *C.BIGNUM
	value := C.CString(wt.Value)
	if C.BN_hex2bn(&bnValue, value) == 0 {
		log.Fatal("Failed to set bnValue")
	}
	C.free(unsafe.Pointer(value))
	defer C.BN_free(bnValue)

	ret := C.BN_is_prime_ex(bnValue, C.BN_prime_checks, (*C.BN_CTX)(unsafe.Pointer(nil)), (*C.BN_GENCB)(unsafe.Pointer(nil)))
	success := wt.Result == "acceptable" || (ret == 0 && wt.Result == "invalid") || (ret == 1 && wt.Result == "valid")
	if !success {
		fmt.Printf("FAIL: Test case %d (%q) %v failed - got %d, want %v\n", wt.TCID, wt.Comment, wt.Flags, ret, wt.Result)
	}
	return success
}

func runPrimalityTestGroup(algorithm string, wtg *wycheproofTestGroupPrimality) bool {
	fmt.Printf("Running %v test group...\n", algorithm)

	success := true
	for _, wt := range wtg.Tests {
		if !runPrimalityTest(wt) {
			success = false
		}
	}
	return success
}

func runRsaesOaepTest(rsa *C.RSA, sha *C.EVP_MD, mgfSha *C.EVP_MD, wt *wycheproofTestRsaes) bool {
	ct, err := hex.DecodeString(wt.CT)
	if err != nil {
		log.Fatalf("Failed to decode cipher text %q: %v", wt.CT, err)
	}
	ctLen := len(ct)
	if ctLen == 0 {
		ct = append(ct, 0)
	}

	rsaSize := C.RSA_size(rsa)
	decrypted := make([]byte, rsaSize)

	success := true

	ret := C.RSA_private_decrypt(C.int(ctLen), (*C.uchar)(unsafe.Pointer(&ct[0])), (*C.uchar)(unsafe.Pointer(&decrypted[0])), rsa, C.RSA_NO_PADDING)

	if ret != rsaSize {
		success = (wt.Result == "invalid")

		if !success {
			fmt.Printf("FAIL: Test case %d (%q) %v - got %d, want %d. Expected: %v\n", wt.TCID, wt.Comment, wt.Flags, ret, rsaSize, wt.Result)
		}
		return success
	}

	label, err := hex.DecodeString(wt.Label)
	if err != nil {
		log.Fatalf("Failed to decode label %q: %v", wt.Label, err)
	}
	labelLen := len(label)
	if labelLen == 0 {
		label = append(label, 0)
	}

	msg, err := hex.DecodeString(wt.Msg)
	if err != nil {
		log.Fatalf("Failed to decode message %q: %v", wt.Msg, err)
	}
	msgLen := len(msg)

	to := make([]byte, rsaSize)

	ret = C.RSA_padding_check_PKCS1_OAEP_mgf1((*C.uchar)(unsafe.Pointer(&to[0])), C.int(rsaSize), (*C.uchar)(unsafe.Pointer(&decrypted[0])), C.int(rsaSize), C.int(rsaSize), (*C.uchar)(unsafe.Pointer(&label[0])), C.int(labelLen), sha, mgfSha)

	if int(ret) != msgLen {
		success = (wt.Result == "invalid")

		if !success {
			fmt.Printf("FAIL: Test case %d (%q) %v - got %d, want %d. Expected: %v\n", wt.TCID, wt.Comment, wt.Flags, ret, rsaSize, wt.Result)
		}
		return success
	}

	to = to[:msgLen]
	if !bytes.Equal(msg, to) {
		success = false
		fmt.Printf("FAIL: Test case %d (%q) %v - expected and calculated message differ. Expected: %v", wt.TCID, wt.Comment, wt.Flags, wt.Result)
	}

	return success
}

func runRsaesOaepTestGroup(algorithm string, wtg *wycheproofTestGroupRsaesOaep) bool {
	fmt.Printf("Running %v test group %v with key size %d MGF %v and %v...\n",
		algorithm, wtg.Type, wtg.KeySize, wtg.MGFSHA, wtg.SHA)

	rsa := C.RSA_new()
	if rsa == nil {
		log.Fatal("RSA_new failed")
	}
	defer C.RSA_free(rsa)

	d := C.CString(wtg.D)
	var rsaD *C.BIGNUM
	defer C.BN_free(rsaD)
	if C.BN_hex2bn(&rsaD, d) == 0 {
		log.Fatal("Failed to set RSA d")
	}
	C.free(unsafe.Pointer(d))

	e := C.CString(wtg.E)
	var rsaE *C.BIGNUM
	defer C.BN_free(rsaE)
	if C.BN_hex2bn(&rsaE, e) == 0 {
		log.Fatal("Failed to set RSA e")
	}
	C.free(unsafe.Pointer(e))

	n := C.CString(wtg.N)
	var rsaN *C.BIGNUM
	defer C.BN_free(rsaN)
	if C.BN_hex2bn(&rsaN, n) == 0 {
		log.Fatal("Failed to set RSA n")
	}
	C.free(unsafe.Pointer(n))

	if C.RSA_set0_key(rsa, rsaN, rsaE, rsaD) == 0 {
		log.Fatal("RSA_set0_key failed")
	}
	rsaN = nil
	rsaE = nil
	rsaD = nil

	sha, err := hashEvpMdFromString(wtg.SHA)
	if err != nil {
		log.Fatalf("Failed to get hash: %v", err)
	}

	mgfSha, err := hashEvpMdFromString(wtg.MGFSHA)
	if err != nil {
		log.Fatalf("Failed to get MGF hash: %v", err)
	}

	success := true
	for _, wt := range wtg.Tests {
		if !runRsaesOaepTest(rsa, sha, mgfSha, wt) {
			success = false
		}
	}
	return success
}

func runRsaesPkcs1Test(rsa *C.RSA, wt *wycheproofTestRsaes) bool {
	ct, err := hex.DecodeString(wt.CT)
	if err != nil {
		log.Fatalf("Failed to decode cipher text %q: %v", wt.CT, err)
	}
	ctLen := len(ct)
	if ctLen == 0 {
		ct = append(ct, 0)
	}

	rsaSize := C.RSA_size(rsa)
	decrypted := make([]byte, rsaSize)

	success := true

	ret := C.RSA_private_decrypt(C.int(ctLen), (*C.uchar)(unsafe.Pointer(&ct[0])), (*C.uchar)(unsafe.Pointer(&decrypted[0])), rsa, C.RSA_PKCS1_PADDING)

	if ret == -1 {
		success = (wt.Result == "invalid")

		if !success {
			fmt.Printf("FAIL: Test case %d (%q) %v - got %d, want %d. Expected: %v\n", wt.TCID, wt.Comment, wt.Flags, ret, len(wt.Msg)/2, wt.Result)
		}
		return success
	}

	msg, err := hex.DecodeString(wt.Msg)
	if err != nil {
		log.Fatalf("Failed to decode message %q: %v", wt.Msg, err)
	}

	if int(ret) != len(msg) {
		success = false
		fmt.Printf("FAIL: Test case %d (%q) %v - got %d, want %d. Expected: %v\n", wt.TCID, wt.Comment, wt.Flags, ret, len(msg), wt.Result)
	} else if !bytes.Equal(msg, decrypted[:len(msg)]) {
		success = false
		fmt.Printf("FAIL: Test case %d (%q) %v - expected and calculated message differ. Expected: %v", wt.TCID, wt.Comment, wt.Flags, wt.Result)
	}

	return success
}

func runRsaesPkcs1TestGroup(algorithm string, wtg *wycheproofTestGroupRsaesPkcs1) bool {
	fmt.Printf("Running %v test group %v with key size %d...\n", algorithm, wtg.Type, wtg.KeySize)
	rsa := C.RSA_new()
	if rsa == nil {
		log.Fatal("RSA_new failed")
	}
	defer C.RSA_free(rsa)

	d := C.CString(wtg.D)
	var rsaD *C.BIGNUM
	defer C.BN_free(rsaD)
	if C.BN_hex2bn(&rsaD, d) == 0 {
		log.Fatal("Failed to set RSA d")
	}
	C.free(unsafe.Pointer(d))

	e := C.CString(wtg.E)
	var rsaE *C.BIGNUM
	defer C.BN_free(rsaE)
	if C.BN_hex2bn(&rsaE, e) == 0 {
		log.Fatal("Failed to set RSA e")
	}
	C.free(unsafe.Pointer(e))

	n := C.CString(wtg.N)
	var rsaN *C.BIGNUM
	defer C.BN_free(rsaN)
	if C.BN_hex2bn(&rsaN, n) == 0 {
		log.Fatal("Failed to set RSA n")
	}
	C.free(unsafe.Pointer(n))

	if C.RSA_set0_key(rsa, rsaN, rsaE, rsaD) == 0 {
		log.Fatal("RSA_set0_key failed")
	}
	rsaN = nil
	rsaE = nil
	rsaD = nil

	success := true
	for _, wt := range wtg.Tests {
		if !runRsaesPkcs1Test(rsa, wt) {
			success = false
		}
	}
	return success
}

func runRsassaTest(rsa *C.RSA, sha *C.EVP_MD, mgfSha *C.EVP_MD, sLen int, wt *wycheproofTestRsassa) bool {
	msg, err := hex.DecodeString(wt.Msg)
	if err != nil {
		log.Fatalf("Failed to decode message %q: %v", wt.Msg, err)
	}

	msg, _, err = hashEvpDigestMessage(sha, msg)
	if err != nil {
		log.Fatalf("%v", err)
	}

	sig, err := hex.DecodeString(wt.Sig)
	if err != nil {
		log.Fatalf("Failed to decode signature %q: %v", wt.Sig, err)
	}

	sigLen := len(sig)
	if sigLen == 0 {
		sig = append(sig, 0)
	}

	sigOut := make([]byte, C.RSA_size(rsa)-11)
	if sigLen == 0 {
		sigOut = append(sigOut, 0)
	}

	ret := C.RSA_public_decrypt(C.int(sigLen), (*C.uchar)(unsafe.Pointer(&sig[0])),
		(*C.uchar)(unsafe.Pointer(&sigOut[0])), rsa, C.RSA_NO_PADDING)
	if ret == -1 {
		if wt.Result == "invalid" {
			return true
		}
		fmt.Printf("FAIL: Test case %d (%q) %v - RSA_public_decrypt() = %d, want %v\n",
			wt.TCID, wt.Comment, wt.Flags, int(ret), wt.Result)
		return false
	}

	ret = C.RSA_verify_PKCS1_PSS_mgf1(rsa, (*C.uchar)(unsafe.Pointer(&msg[0])), sha, mgfSha,
		(*C.uchar)(unsafe.Pointer(&sigOut[0])), C.int(sLen))

	success := false
	if ret == 1 && (wt.Result == "valid" || wt.Result == "acceptable") {
		// All acceptable cases that pass use SHA-1 and are flagged:
		// "WeakHash" : "The key for this test vector uses a weak hash function."
		success = true
	} else if ret == 0 && (wt.Result == "invalid" || wt.Result == "acceptable") {
		success = true
	} else {
		fmt.Printf("FAIL: Test case %d (%q) %v - RSA_verify_PKCS1_PSS_mgf1() = %d, want %v\n",
			wt.TCID, wt.Comment, wt.Flags, int(ret), wt.Result)
	}
	return success
}

func runRsassaTestGroup(algorithm string, wtg *wycheproofTestGroupRsassa) bool {
	fmt.Printf("Running %v test group %v with key size %d and %v...\n",
		algorithm, wtg.Type, wtg.KeySize, wtg.SHA)
	rsa := C.RSA_new()
	if rsa == nil {
		log.Fatal("RSA_new failed")
	}
	defer C.RSA_free(rsa)

	e := C.CString(wtg.E)
	var rsaE *C.BIGNUM
	defer C.BN_free(rsaE)
	if C.BN_hex2bn(&rsaE, e) == 0 {
		log.Fatal("Failed to set RSA e")
	}
	C.free(unsafe.Pointer(e))

	n := C.CString(wtg.N)
	var rsaN *C.BIGNUM
	defer C.BN_free(rsaN)
	if C.BN_hex2bn(&rsaN, n) == 0 {
		log.Fatal("Failed to set RSA n")
	}
	C.free(unsafe.Pointer(n))

	if C.RSA_set0_key(rsa, rsaN, rsaE, nil) == 0 {
		log.Fatal("RSA_set0_key failed")
	}
	rsaN = nil
	rsaE = nil

	sha, err := hashEvpMdFromString(wtg.SHA)
	if err != nil {
		log.Fatalf("Failed to get hash: %v", err)
	}

	mgfSha, err := hashEvpMdFromString(wtg.MGFSHA)
	if err != nil {
		log.Fatalf("Failed to get MGF hash: %v", err)
	}

	success := true
	for _, wt := range wtg.Tests {
		if !runRsassaTest(rsa, sha, mgfSha, wtg.SLen, wt) {
			success = false
		}
	}
	return success
}

func runRSATest(rsa *C.RSA, md *C.EVP_MD, nid int, wt *wycheproofTestRSA) bool {
	msg, err := hex.DecodeString(wt.Msg)
	if err != nil {
		log.Fatalf("Failed to decode message %q: %v", wt.Msg, err)
	}

	msg, msgLen, err := hashEvpDigestMessage(md, msg)
	if err != nil {
		log.Fatalf("%v", err)
	}

	sig, err := hex.DecodeString(wt.Sig)
	if err != nil {
		log.Fatalf("Failed to decode signature %q: %v", wt.Sig, err)
	}

	sigLen := len(sig)
	if sigLen == 0 {
		sig = append(sig, 0)
	}

	ret := C.RSA_verify(C.int(nid), (*C.uchar)(unsafe.Pointer(&msg[0])), C.uint(msgLen),
		(*C.uchar)(unsafe.Pointer(&sig[0])), C.uint(sigLen), rsa)

	// XXX audit acceptable cases...
	success := true
	if ret == 1 != (wt.Result == "valid") && wt.Result != "acceptable" {
		fmt.Printf("FAIL: Test case %d (%q) %v - RSA_verify() = %d, want %v\n",
			wt.TCID, wt.Comment, wt.Flags, int(ret), wt.Result)
		success = false
	}
	return success
}

func runRSATestGroup(algorithm string, wtg *wycheproofTestGroupRSA) bool {
	fmt.Printf("Running %v test group %v with key size %d and %v...\n",
		algorithm, wtg.Type, wtg.KeySize, wtg.SHA)

	rsa := C.RSA_new()
	if rsa == nil {
		log.Fatal("RSA_new failed")
	}
	defer C.RSA_free(rsa)

	e := C.CString(wtg.E)
	var rsaE *C.BIGNUM
	defer C.BN_free(rsaE)
	if C.BN_hex2bn(&rsaE, e) == 0 {
		log.Fatal("Failed to set RSA e")
	}
	C.free(unsafe.Pointer(e))

	n := C.CString(wtg.N)
	var rsaN *C.BIGNUM
	defer C.BN_free(rsaN)
	if C.BN_hex2bn(&rsaN, n) == 0 {
		log.Fatal("Failed to set RSA n")
	}
	C.free(unsafe.Pointer(n))

	if C.RSA_set0_key(rsa, rsaN, rsaE, nil) == 0 {
		log.Fatal("RSA_set0_key failed")
	}
	rsaN = nil
	rsaE = nil

	nid, err := nidFromString(wtg.SHA)
	if err != nil {
		log.Fatalf("Failed to get MD NID: %v", err)
	}
	md, err := hashEvpMdFromString(wtg.SHA)
	if err != nil {
		log.Fatalf("Failed to get hash: %v", err)
	}

	success := true
	for _, wt := range wtg.Tests {
		if !runRSATest(rsa, md, nid, wt) {
			success = false
		}
	}
	return success
}

func runX25519Test(wt *wycheproofTestX25519) bool {
	public, err := hex.DecodeString(wt.Public)
	if err != nil {
		log.Fatalf("Failed to decode public %q: %v", wt.Public, err)
	}
	private, err := hex.DecodeString(wt.Private)
	if err != nil {
		log.Fatalf("Failed to decode private %q: %v", wt.Private, err)
	}
	shared, err := hex.DecodeString(wt.Shared)
	if err != nil {
		log.Fatalf("Failed to decode shared %q: %v", wt.Shared, err)
	}

	got := make([]byte, C.X25519_KEY_LENGTH)
	result := true

	if C.X25519((*C.uint8_t)(unsafe.Pointer(&got[0])), (*C.uint8_t)(unsafe.Pointer(&private[0])), (*C.uint8_t)(unsafe.Pointer(&public[0]))) != 1 {
		result = false
	} else {
		result = bytes.Equal(got, shared)
	}

	// XXX audit acceptable cases...
	success := true
	if result != (wt.Result == "valid") && wt.Result != "acceptable" {
		fmt.Printf("FAIL: Test case %d (%q) %v - X25519(), want %v\n",
			wt.TCID, wt.Comment, wt.Flags, wt.Result)
		success = false
	}
	return success
}

func runX25519TestGroup(algorithm string, wtg *wycheproofTestGroupX25519) bool {
	fmt.Printf("Running %v test group with curve %v...\n", algorithm, wtg.Curve)

	success := true
	for _, wt := range wtg.Tests {
		if !runX25519Test(wt) {
			success = false
		}
	}
	return success
}

func runTestVectors(path string, variant testVariant) bool {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read test vectors: %v", err)
	}
	wtv := &wycheproofTestVectors{}
	if err := json.Unmarshal(b, wtv); err != nil {
		log.Fatalf("Failed to unmarshal JSON: %v", err)
	}
	fmt.Printf("Loaded Wycheproof test vectors for %v with %d tests from %q\n",
		wtv.Algorithm, wtv.NumberOfTests, filepath.Base(path))

	success := true
	for i := range wtv.TestGroups {
		testc.runTest(func() bool {
			var wtg interface{}
			switch wtv.Algorithm {
			case "AES-CBC-PKCS5":
				wtg = &wycheproofTestGroupAesCbcPkcs5{}
			case "AES-CCM":
				wtg = &wycheproofTestGroupAead{}
			case "AES-CMAC":
				wtg = &wycheproofTestGroupAesCmac{}
			case "AES-GCM":
				wtg = &wycheproofTestGroupAead{}
			case "CHACHA20-POLY1305", "XCHACHA20-POLY1305":
				wtg = &wycheproofTestGroupAead{}
			case "DSA":
				wtg = &wycheproofTestGroupDSA{}
			case "ECDH":
				switch variant {
				case Webcrypto:
					wtg = &wycheproofTestGroupECDHWebCrypto{}
				default:
					wtg = &wycheproofTestGroupECDH{}
				}
			case "ECDSA":
				switch variant {
				case Webcrypto:
					wtg = &wycheproofTestGroupECDSAWebCrypto{}
				default:
					wtg = &wycheproofTestGroupECDSA{}
				}
			case "EDDSA":
				wtg = &wycheproofTestGroupEdDSA{}
			case "HKDF-SHA-1", "HKDF-SHA-256", "HKDF-SHA-384", "HKDF-SHA-512":
				wtg = &wycheproofTestGroupHkdf{}
			case "HMACSHA1", "HMACSHA224", "HMACSHA256", "HMACSHA384", "HMACSHA512", "HMACSHA3-224", "HMACSHA3-256", "HMACSHA3-384", "HMACSHA3-512":
				wtg = &wycheproofTestGroupHmac{}
			case "KW":
				wtg = &wycheproofTestGroupKW{}
			case "PrimalityTest":
				wtg = &wycheproofTestGroupPrimality{}
			case "RSAES-OAEP":
				wtg = &wycheproofTestGroupRsaesOaep{}
			case "RSAES-PKCS1-v1_5":
				wtg = &wycheproofTestGroupRsaesPkcs1{}
			case "RSASSA-PSS":
				wtg = &wycheproofTestGroupRsassa{}
			case "RSASSA-PKCS1-v1_5", "RSASig":
				wtg = &wycheproofTestGroupRSA{}
			case "XDH", "X25519":
				wtg = &wycheproofTestGroupX25519{}
			default:
				log.Printf("INFO: Unknown test vector algorithm %q", wtv.Algorithm)
				return false
			}

			if err := json.Unmarshal(wtv.TestGroups[i], wtg); err != nil {
				log.Fatalf("Failed to unmarshal test groups JSON: %v", err)
			}
			switch wtv.Algorithm {
			case "AES-CBC-PKCS5":
				return runAesCbcPkcs5TestGroup(wtv.Algorithm, wtg.(*wycheproofTestGroupAesCbcPkcs5))
			case "AES-CCM":
				return runAesAeadTestGroup(wtv.Algorithm, wtg.(*wycheproofTestGroupAead))
			case "AES-CMAC":
				return runAesCmacTestGroup(wtv.Algorithm, wtg.(*wycheproofTestGroupAesCmac))
			case "AES-GCM":
				return runAesAeadTestGroup(wtv.Algorithm, wtg.(*wycheproofTestGroupAead))
			case "CHACHA20-POLY1305", "XCHACHA20-POLY1305":
				return runChaCha20Poly1305TestGroup(wtv.Algorithm, wtg.(*wycheproofTestGroupAead))
			case "DSA":
				return runDSATestGroup(wtv.Algorithm, variant, wtg.(*wycheproofTestGroupDSA))
			case "ECDH":
				switch variant {
				case Webcrypto:
					return runECDHWebCryptoTestGroup(wtv.Algorithm, wtg.(*wycheproofTestGroupECDHWebCrypto))
				default:
					return runECDHTestGroup(wtv.Algorithm, variant, wtg.(*wycheproofTestGroupECDH))
				}
			case "ECDSA":
				switch variant {
				case Webcrypto:
					return runECDSAWebCryptoTestGroup(wtv.Algorithm, wtg.(*wycheproofTestGroupECDSAWebCrypto))
				default:
					return runECDSATestGroup(wtv.Algorithm, variant, wtg.(*wycheproofTestGroupECDSA))
				}
			case "EDDSA":
				return runEdDSATestGroup(wtv.Algorithm, wtg.(*wycheproofTestGroupEdDSA))
			case "HKDF-SHA-1", "HKDF-SHA-256", "HKDF-SHA-384", "HKDF-SHA-512":
				return runHkdfTestGroup(wtv.Algorithm, wtg.(*wycheproofTestGroupHkdf))
			case "HMACSHA1", "HMACSHA224", "HMACSHA256", "HMACSHA384", "HMACSHA512", "HMACSHA3-224", "HMACSHA3-256", "HMACSHA3-384", "HMACSHA3-512":
				return runHmacTestGroup(wtv.Algorithm, wtg.(*wycheproofTestGroupHmac))
			case "KW":
				return runKWTestGroup(wtv.Algorithm, wtg.(*wycheproofTestGroupKW))
			case "PrimalityTest":
				return runPrimalityTestGroup(wtv.Algorithm, wtg.(*wycheproofTestGroupPrimality))
			case "RSAES-OAEP":
				return runRsaesOaepTestGroup(wtv.Algorithm, wtg.(*wycheproofTestGroupRsaesOaep))
			case "RSAES-PKCS1-v1_5":
				return runRsaesPkcs1TestGroup(wtv.Algorithm, wtg.(*wycheproofTestGroupRsaesPkcs1))
			case "RSASSA-PSS":
				return runRsassaTestGroup(wtv.Algorithm, wtg.(*wycheproofTestGroupRsassa))
			case "RSASSA-PKCS1-v1_5", "RSASig":
				return runRSATestGroup(wtv.Algorithm, wtg.(*wycheproofTestGroupRSA))
			case "XDH", "X25519":
				return runX25519TestGroup(wtv.Algorithm, wtg.(*wycheproofTestGroupX25519))
			default:
				log.Fatalf("Unknown test vector algorithm %q", wtv.Algorithm)
				return false
			}
		})
	}
	for _ = range wtv.TestGroups {
		result := <-testc.resultCh
		if !result {
			success = false
		}
	}
	return success
}

type testCoordinator struct {
	testFuncCh chan func() bool
	resultCh   chan bool
}

func newTestCoordinator() *testCoordinator {
	runnerCount := runtime.NumCPU()
	tc := &testCoordinator{
		testFuncCh: make(chan func() bool, runnerCount),
		resultCh:   make(chan bool, 1024),
	}
	for i := 0; i < runnerCount; i++ {
		go tc.testRunner(tc.testFuncCh, tc.resultCh)
	}
	return tc
}

func (tc *testCoordinator) testRunner(testFuncCh <-chan func() bool, resultCh chan<- bool) {
	for testFunc := range testFuncCh {
		select {
		case resultCh <- testFunc():
		default:
			log.Fatal("result channel is full")
		}
	}
}

func (tc *testCoordinator) runTest(testFunc func() bool) {
	tc.testFuncCh <- testFunc
}

func (tc *testCoordinator) shutdown() {
	close(tc.testFuncCh)
}

func main() {
	if _, err := os.Stat(testVectorPath); os.IsNotExist(err) {
		fmt.Printf("package wycheproof-testvectors is required for this regress\n")
		fmt.Printf("SKIPPED\n")
		os.Exit(0)
	}

	tests := []struct {
		name    string
		pattern string
		variant testVariant
	}{
		{"AES", "aes_[cg]*[^xv]_test.json", Normal}, // Skip AES-EAX, AES-GCM-SIV and AES-SIV-CMAC.
		{"ChaCha20-Poly1305", "chacha20_poly1305_test.json", Normal},
		{"DSA", "dsa_*test.json", Normal},
		{"DSA", "dsa_*_p1363_test.json", P1363},
		{"ECDH", "ecdh_test.json", Normal},
		{"ECDH", "ecdh_[^w_]*_test.json", Normal},
		{"ECDH EcPoint", "ecdh_*_ecpoint_test.json", EcPoint},
		{"ECDH webcrypto", "ecdh_webcrypto_test.json", Webcrypto},
		{"ECDSA", "ecdsa_test.json", Normal},
		{"ECDSA", "ecdsa_[^w]*test.json", Normal},
		{"ECDSA P1363", "ecdsa_*_p1363_test.json", P1363},
		{"ECDSA webcrypto", "ecdsa_webcrypto_test.json", Webcrypto},
		{"EDDSA", "eddsa_test.json", Normal},
		{"ED448", "ed448_test.json", Skip},
		{"HKDF", "hkdf_sha*_test.json", Normal},
		{"HMAC", "hmac_sha*_test.json", Normal},
		// uncomment once package builds have caught up:
		// {"JSON webcrypto", "json_web_*_test.json", Skip},
		{"KW", "kw_test.json", Normal},
		{"Primality test", "primality_test.json", Normal},
		{"RSA", "rsa_*test.json", Normal},
		{"X25519", "x25519_test.json", Normal},
		{"X25519 ASN", "x25519_asn_test.json", Skip},
		{"X25519 JWK", "x25519_jwk_test.json", Skip},
		{"X25519 PEM", "x25519_pem_test.json", Skip},
		{"XCHACHA20-POLY1305", "xchacha20_poly1305_test.json", Normal},
	}

	success := true

	var wg sync.WaitGroup

	vectorsRateLimitCh := make(chan bool, 4)
	for i := 0; i < cap(vectorsRateLimitCh); i++ {
		vectorsRateLimitCh <- true
	}
	resultCh := make(chan bool, 1024)

	testc = newTestCoordinator()

	skipNormal := regexp.MustCompile(`_(ecpoint|p1363|sect\d{3}[rk]1)_`)

	for _, test := range tests {
		tvs, err := filepath.Glob(filepath.Join(testVectorPath, test.pattern))
		if err != nil {
			log.Fatalf("Failed to glob %v test vectors: %v", test.name, err)
		}
		if len(tvs) == 0 {
			log.Fatalf("Failed to find %v test vectors at %q\n", test.name, testVectorPath)
		}
		for _, tv := range tvs {
			if test.variant == Skip || (test.variant == Normal && skipNormal.Match([]byte(tv))) {
				fmt.Printf("INFO: Skipping tests from \"%s\"\n", strings.TrimPrefix(tv, testVectorPath+"/"))
				continue
			}
			wg.Add(1)
			<-vectorsRateLimitCh
			go func(tv string, variant testVariant) {
				select {
				case resultCh <- runTestVectors(tv, variant):
				default:
					log.Fatal("result channel is full")
				}
				vectorsRateLimitCh <- true
				wg.Done()
			}(tv, test.variant)
		}
	}

	wg.Wait()
	close(resultCh)

	for result := range resultCh {
		if !result {
			success = false
		}
	}

	testc.shutdown()

	C.OPENSSL_cleanup()

	if !success {
		os.Exit(1)
	}
}
