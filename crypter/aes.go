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

func aesSessionEncrypt(key []byte, plain io.Reader, cipherWriter io.Writer) (count int, err error) {

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return 0, err
	}
	if _, err = cipherWriter.Write(iv); err != nil {
		return 0, err
	}
	ci, err := aes.NewCipher(key)
	if err != nil {
		return 0, err
	}

	for {
		block := make([]byte, aes.BlockSize)
		cipherBlock := make([]byte, aes.BlockSize)
		c, perr := plain.Read(block)
		if c == 0 && perr == io.EOF {
			break
		}
		if c < aes.BlockSize {
			block = block[:c]
			pkcs7Padding(&block)
		}

		for i := 0; i < aes.BlockSize; i++ {
			cipherBlock[i] = block[i] ^ iv[i]
		}

		ci.Encrypt(cipherBlock, cipherBlock)

		iv = cipherBlock

		c, err = cipherWriter.Write(cipherBlock)
		if err != nil {
			return count, err
		}
		count += c
		if perr == io.EOF {
			break
		}

	}
	return
}

func aesSessionDecrypt(key []byte, cipherReader io.Reader, plain *decryptedFile) (origin string, count int, err error) {

	ci, err := aes.NewCipher(key)
	if err != nil {
		return "", 0, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err = cipherReader.Read(iv); err != nil {
		return "", 0, err
	}

	block := make([]byte, aes.BlockSize)
	c, err := cipherReader.Read(block)

	if err != nil {
		return "", 0, errors.New("empty file or read error")
	}

	for {

		newBlock := make([]byte, aes.BlockSize)
		newC, err := cipherReader.Read(newBlock)

		plainBlock := make([]byte, aes.BlockSize)
		ci.Decrypt(plainBlock, block)
		for i := 0; i < aes.BlockSize; i++ {
			plainBlock[i] = plainBlock[i] ^ iv[i]
		}
		iv = block

		if err == io.EOF {
			pkcs7Unpadding(&plainBlock)
			c, err = plain.Write(plainBlock)
			if err != nil {
				return "", 0, err
			}
			count += c
			break
		}

		if c < aes.BlockSize {
			return "", 0, errors.New("input data is not correct")
		}

		c, err = plain.Write(plainBlock)
		if err != nil {
			return "", 0, err
		}
		count += c

		c = newC
		block = newBlock
	}

	origin = string(plain.name)
	return
}
