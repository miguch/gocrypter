package crypter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const BLOCK_SIZE = aes.BlockSize

func pkcs7Padding(blockData *[]byte) {
	PaddingBytes := BLOCK_SIZE - len(*blockData)%BLOCK_SIZE
	*blockData = append(*blockData, bytes.Repeat([]byte{byte(PaddingBytes)}, PaddingBytes)...)
}

//Delete n bytes from the end of the input blocks where n equals
// to the last byte of the input block.
func pkcs7Unpadding(blockData *[]byte) {
	length := len(*blockData)
	unpadding := int((*blockData)[length-1])
	*blockData = (*blockData)[:(length - unpadding)]
}

func generateAesKey() []byte {
	//AES-256
	key := make([]byte, 32)
	rand.Read(key)
	return key
}

func aesEncrypt(plainText []byte) (key, cipherText []byte, err error) {
	key = generateAesKey()

	pkcs7Padding(&plainText)

	block, err := aes.NewCipher(key)
	cipherText = make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCBCEncrypter(block, iv)
	stream.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	return
}

func aesDecrypt(key, cipherText []byte) (plainText []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("ciphertext block size is too short")
		return
	}
	plainText = make([]byte, len(cipherText)-aes.BlockSize)

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCBCDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.CryptBlocks(plainText, cipherText)

	pkcs7Unpadding(&plainText)
	return
}
