package main

import (
	"encoding/binary"
	"fmt"
	"github.com/miguch/gocrypter/crypter"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"io/ioutil"
	"os"
	"path"
)

var crypt *crypter.Crypter

func encryptFile(filename string, passphrase string) (cipher []byte, err error) {
	nameLen := [4]byte{}
	binary.LittleEndian.PutUint32(nameLen[:], uint32(len(filename)))
	nameBlock := make([]byte, 0, 4 + len(filename))
	nameBlock = append(nameBlock, nameLen[:]...)
	nameBlock = append(nameBlock, []byte(filename)...)

	plainData, err := ioutil.ReadFile(filename)
	if err != nil {
		return []byte{}, err
	}

	return crypt.Encrypt(append(nameBlock, plainData...), crypt.GetPublicKey())
}

func decryptFile(filename string, passphrase string) (originName string, plain []byte,  err error) {
	cipher, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", []byte{}, err
	}
	if len(cipher) <= 4 {
		return "", []byte{}, errors.New(fmt.Sprintf("Skip %v", filename))
	}

	plainData, err := crypt.Decrypt(cipher)
	if err != nil {
		return "", []byte{}, err
	}

	nameLen := binary.LittleEndian.Uint32(plainData[:4])
	originName = string(plainData[4:4 + nameLen])
	plain = plainData[4+nameLen:]
	return
}

const encryptPath = "crypted"
const decryptPath = "output"

func main()  {
	files, err := ioutil.ReadDir("./")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load directory: %v\n", err)
		os.Exit(1)
	}

	decryptModePtr := pflag.BoolP("decrypt", "d", false, "Specify to decrypt current directory.")
	pflag.Parse()
	decryptMode := *decryptModePtr
	if len(pflag.Args()) == 0 {
		fmt.Fprintf(os.Stderr, "A passphrase must be specified!\n")
		os.Exit(1)
	}
	passPhrase := pflag.Arg(0)

	var outputPath string

	if decryptMode {
		outputPath = decryptPath
		fmt.Println("Decrypting...")
	} else {
		outputPath = encryptPath
		fmt.Println("Encrypting...")
	}

	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		err = os.Mkdir(outputPath, os.ModePerm)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create output directory: %v\n", err)
			os.Exit(1)
		}
	}

	crypt, err = crypter.NewCrypter(passPhrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create crypter: %v\n", err)
		os.Exit(1)
	}

	for ind, f := range files {
		if decryptMode {

			name, plain, err := decryptFile(f.Name(), passPhrase)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Skip %v: %v\n", f.Name(), err)
				continue
			}
			err = ioutil.WriteFile(path.Join(outputPath, name), plain, 0644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to create output file: %v\n", err)
				continue
			}
		}else {

			ci, err := encryptFile(f.Name(), passPhrase)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Skip %v: %v\n", f.Name(), err)
				continue
			}

			err = ioutil.WriteFile(path.Join(outputPath, fmt.Sprintf("%v.ci", ind)), ci, 0644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to create output file: %v\n", err)
				continue
			}
		}
	}
}

