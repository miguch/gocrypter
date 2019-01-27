package crypter

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"golang.org/x/crypto/pbkdf2"
	"hash/fnv"
	"io"
	"math/rand"
	"strconv"
)

func getBytesHash64(str []byte) uint64 {
	h := fnv.New64a()
	h.Write([]byte(str))
	return h.Sum64()
}

func getBytesHash32(str []byte) uint32 {
	h := fnv.New32a()
	h.Write([]byte(str))
	return h.Sum32()
}

type Crypter struct {
	Passphrase    string
	RsaPrivateKey *rsa.PrivateKey
	randReader    io.Reader
}

func NewCrypter(passphrase string) (*Crypter, error) {
	salt := strconv.Itoa(len(passphrase) + int(getBytesHash32([]byte(passphrase))))

	dk := pbkdf2.Key([]byte(passphrase), []byte(salt), 10000, 64, sha256.New)
	seed := int64(binary.LittleEndian.Uint64(dk))
	randReader := rand.New(rand.NewSource(seed))

	key, err := generateMultiPrimeKey(randReader, 2, 2048)
	if err != nil {
		return nil, err
	}
	return &Crypter{
		Passphrase:    passphrase,
		RsaPrivateKey: key,
		randReader:    randReader,
	}, nil
}

func (cc *Crypter) Encrypt(plainText, publicKey []byte) ([]byte, error) {
	pubKey, err := x509.ParsePKCS1PublicKey(publicKey)
	if err != nil {
		return []byte{}, err
	}
	key, cipher, err := aesEncrypt(plainText)
	if err != nil {
		return []byte{}, err
	}
	encryptedKey, err := rsa.EncryptPKCS1v15(cc.randReader, pubKey, key)
	if err != nil {
		return []byte{}, err
	}
	cipher = append(encryptedKey, cipher...)

	return cipher, nil
}

func (cc *Crypter) Decrypt(cipherText []byte) ([]byte, error) {
	const EncryptedKeyLength = 256
	//First 256 bytes is the encrypted AES key
	encryptedKey := cipherText[:EncryptedKeyLength]
	cipherText = cipherText[EncryptedKeyLength:]
	key, err := cc.RsaPrivateKey.Decrypt(cc.randReader, encryptedKey, nil)
	if err != nil {
		return []byte{}, err
	}
	return aesDecrypt(key, cipherText)
}

func (cc *Crypter) GetPublicKey() []byte {
	keyBytes := x509.MarshalPKCS1PublicKey(&cc.RsaPrivateKey.PublicKey)
	return keyBytes
}

func (cc *Crypter) EncryptString(plainText, publicKey string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return "", err
	}
	res, err := cc.Encrypt([]byte(plainText), key)
	return base64.StdEncoding.EncodeToString(res), err
}

func (cc *Crypter) DecryptString(cipherText string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	res, err := cc.Decrypt(data)
	return string(res), err
}

func (cc *Crypter) SignMessage(message []byte) ([]byte, error) {
	hashed := sha256.Sum256(message)
	return rsa.SignPKCS1v15(cc.randReader, cc.RsaPrivateKey, crypto.SHA256, hashed[:])
}

func (cc *Crypter) SignMessageString(message string) (string, error) {
	data, err := cc.SignMessage([]byte(message))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func (cc *Crypter) VerifySigning(message, signature, publicKey []byte) error {
	pubKey, err := x509.ParsePKCS1PublicKey(publicKey)
	if err != nil {
		return err
	}
	hashed := sha256.Sum256(message)
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature)
}

func (cc *Crypter) VerifySigningString(message, signature, publicKey string) error {
	sigData, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	key, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return err
	}
	return cc.VerifySigning([]byte(message), sigData, key)
}
