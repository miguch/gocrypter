package crypter

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"github.com/pkg/errors"
	"os"
	"path"
)

type CryptSession struct {
	cc *Crypter
}

type srcFile struct {
	file   *os.File
	header []byte
	index  int
}

func NewSrcFile(file *os.File, name string) *srcFile {
	header := make([]byte, 0, 4+len(name))
	nameLen := [4]byte{}
	binary.LittleEndian.PutUint32(nameLen[:], uint32(len(name)))
	header = append(header, nameLen[:]...)
	header = append(header, []byte(name)...)
	return &srcFile{
		file,
		header,
		0,
	}
}

func (sf *srcFile) readOneByte() (byte, error) {
	if sf.index < len(sf.header) {
		res := sf.header[sf.index]
		sf.index++
		return res, nil
	} else {
		res := []byte{0x00}
		_, err := sf.file.Read(res)
		if err != nil {
			return 0x00, err
		}
		sf.index++
		return res[0], nil
	}
}

type decryptedFile struct {
	outFile *os.File
	nameLen uint32
	index   uint32
	name    []byte
}

const decryptPath = "output"

func (df *decryptedFile) Write(p []byte) (n int, err error) {
	if df.nameLen+4 <= df.index {
		df.index += uint32(len(p))
		return df.outFile.Write(p)
	}
	consumed := 0
	if len(p) <= 0 {
		return
	}
	if df.index == 0 {
		if len(p) < 4 {
			panic("wrong first write word")
		}
		df.nameLen = binary.LittleEndian.Uint32(p[0:4])
		df.index += 4
		consumed += 4
		df.name = make([]byte, df.nameLen)
	}

	for ; consumed < len(p); consumed++ {

		if df.nameLen+4 > df.index {
			df.name[df.index-4] = p[consumed]
			if df.index == 4+df.nameLen-1 {
				df.outFile, err = os.OpenFile(path.Join(decryptPath, string(df.name)), os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					return 0, err
				}
			}
		} else {
			_, err = df.outFile.Write([]byte{p[consumed]})
			if err != nil {
				return 0, err
			}
		}
		df.index++
	}
	return len(p), nil
}

func (sf *srcFile) Read(p []byte) (n int, err error) {

	if sf.index >= len(sf.header) {
		return sf.file.Read(p)
	}
	for i := 0; i < len(p); i++ {
		b, err := sf.readOneByte()
		if err != nil {
			return i, err
		}
		p[i] = b
	}
	return len(p), nil
}

func NewCryptSession(cc *Crypter) *CryptSession {
	return &CryptSession{
		cc,
	}
}

func (cs *CryptSession) Encrypt(filename string, outname string) error {
	info, err := os.Stat(filename)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return errors.New("is directory")
	}

	file, err := os.Open(filename)
	if err != nil {
		return err
	}

	src := NewSrcFile(file, filename)
	out, err := os.OpenFile(outname, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	key := generateAesKey()
	pubKey, err := x509.ParsePKCS1PublicKey(cs.cc.GetPublicKey())
	if err != nil {
		return err
	}
	enc, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, key)
	if err != nil {
		return err
	}
	_, err = out.Write(enc)
	if err != nil {
		return err
	}

	_, err = aesSessionEncrypt(key, src, out)
	return err
}

func (cs *CryptSession) Decrypt(filename string) (string, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", errors.New("is directory")
	}
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}

	enc := make([]byte, 256)
	_, err = file.Read(enc)
	if err != nil {
		return "", err
	}

	key, err := cs.cc.RsaPrivateKey.Decrypt(rand.Reader, enc, nil)
	if err != nil {
		return "", err
	}

	dec := new(decryptedFile)
	name, _, err := aesSessionDecrypt(key, file, dec)
	return name, err
}
