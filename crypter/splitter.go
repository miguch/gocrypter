package crypter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path"
)

type Splitter struct {
	cc *Crypter
}

func NewSplitter(cc *Crypter) *Splitter {
	return &Splitter{
		cc,
	}
}

func (sp *Splitter) Encrypt(src, dst string) (n int, err error) {
	info, err := os.Stat(src)
	if err != nil {
		return 0, err
	}
	if info.IsDir() {
		return 0, errors.New("is directory")
	}

	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return 0, err
	}

	key := generateAesKey()
	pubKey, err := x509.ParsePKCS1PublicKey(sp.cc.GetPublicKey())
	if err != nil {
		return 0, err
	}
	enc, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, key)
	if err != nil {
		return 0, err
	}

	c, err := out.Write(enc)
	if err != nil {
		return 0, err
	}
	n += c

	block, err := aes.NewCipher(key)
	iv := make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return 0, err
	}

	if _, err = out.Write(iv); err != nil {
		return 0, err
	}
	stream := cipher.NewCBCEncrypter(block, iv)
	nameLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(nameLen, uint32(len(src)))
	c, err = out.Write(nameLen)
	n += c
	nameBytes := []byte(src)
	pkcs7Padding(&nameBytes)
	ciName := make([]byte, len(nameBytes))
	stream.CryptBlocks(ciName, nameBytes)
	c, err = out.Write(ciName)
	n += c

	for {
		//1MB chunk
		block := make([]byte, 1048576*4-15)

		c, perr := in.Read(block)
		if c == 0 && perr == io.EOF {
			break
		}
		block = block[:c]
		pkcs7Padding(&block)
		cipherBlock := make([]byte, len(block))

		stream.CryptBlocks(cipherBlock, block)
		c, err = out.Write(cipherBlock)
		if err != nil {
			return 0, err
		}
		n += c
		if perr == io.EOF {
			break
		}
	}
	return n, nil
}

const EncryptedKeyLength = 256

func (sp *Splitter) Decrypt(src string) (origin string, n int, err error) {
	info, err := os.Stat(src)
	if err != nil {
		return "", 0, err
	}
	if info.IsDir() {
		return "", 0, errors.New("is directory")
	}

	in, err := os.Open(src)
	if err != nil {
		return "", 0, err
	}

	enc := make([]byte, EncryptedKeyLength)
	_, err = in.Read(enc)
	if err != nil {
		return "", 0, err
	}

	key, err := sp.cc.RsaPrivateKey.Decrypt(rand.Reader, enc, nil)
	if err != nil {
		return "", 0, err
	}

	block, err := aes.NewCipher(key)
	iv := make([]byte, aes.BlockSize)
	_, err = in.Read(iv)
	if err != nil {
		return "", 0, err
	}
	stream := cipher.NewCBCDecrypter(block, iv)

	nameLen := make([]byte, 4)
	_, err = in.Read(nameLen)
	if err != nil {
		return "", 0, err
	}
	nLen := binary.LittleEndian.Uint32(nameLen)
	nLen = (nLen/aes.BlockSize + 1) * aes.BlockSize

	ciName := make([]byte, nLen)
	_, err = in.Read(ciName)
	if err != nil {
		return "", 0, err
	}
	name := make([]byte, nLen)
	stream.CryptBlocks(name, ciName)
	pkcs7Unpadding(&name)

	out, err := os.OpenFile(path.Join(decryptPath, string(name)), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return "", 0, err
	}

	for {
		block := make([]byte, 1048576*4)
		c, perr := in.Read(block)
		block = block[:c]
		plainBlock := make([]byte, len(block))
		if c < aes.BlockSize {
			if perr == io.EOF {
				break
			}
			return "", 0, errors.New("data incorrect")
		}
		stream.CryptBlocks(plainBlock, block)
		pkcs7Unpadding(&plainBlock)

		c, err = out.Write(plainBlock)
		if err != nil {
			return "", 0, err
		}
		n += c
		if perr == io.EOF {
			break
		}
	}
	return string(name), n, nil
}
