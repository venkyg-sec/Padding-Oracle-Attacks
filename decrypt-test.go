package main

import ("fmt"
	"io/ioutil"
	"strings"
	"os"
	"crypto/sha256"
	"crypto/aes"
)

func check(e error) {
	if e != nil {
		fmt.Println("\033[91m[!]\033[0m ERROR:",e, "\n")
		show_usage()
		os.Exit(1)
	}
}

func show_usage() {
	fmt.Println("\033[94m[*]\033[0m Authenticated Decryption Tool \033[94m[*]\033[0m")
	fmt.Println("A tool for performing AES-128 CBC Decryption and signature verification using HMAC\n")
	fmt.Println("usage: ./decrypt-test -i <input-file>")
	fmt.Println("Flag\tMeaning")
	fmt.Println("----------------------------------------------------------------")
	fmt.Println("-i\tInput File to be Decrypted")
}

func block_exor(data, iv []byte) []byte {

	result := make([]byte, len(iv))

	for i:=0;i<len(iv);i++ {
		result[i] = data[i] ^ iv[i]
	}

	return result
}

func remove_pad(data []byte) []byte {

	n := data[len(data)-1]
	var pad_len int

	if n == 0 {
		return []byte("INVALID PADDING")
	}
	if n == aes.BlockSize {
		pad_len = aes.BlockSize
	} else {
		pad_len = int(n)
	}

	for i:=1;i<=pad_len;i++ {
		if data[len(data)-i] != byte(n) {
			return []byte("INVALID PADDING")
		}
	}

	unpadded_data := data[0:(len(data)-int(pad_len))]

	return unpadded_data
}

func calc_hmac(data, key []byte) [32]byte {

	var hmac_key []byte
	ipad := make([]byte, sha256.BlockSize)
	opad := make([]byte, sha256.BlockSize)

	for i:=0;i<sha256.BlockSize;i++ {
		ipad[i] = byte(0x36)
		opad[i] = byte(0x5c)
	}

	if len(key) == sha256.BlockSize {
		hmac_key = key

	} else if len(key) < sha256.BlockSize {
		hmac_key = key
		for i:=0;i<(sha256.BlockSize-len(key));i++ {
			hmac_key = append(hmac_key, byte(0x00))
		}

	} else {

		key_sum := sha256.Sum256(key)
		for i:=0;i<(len(key_sum));i++ {
			hmac_key = append(hmac_key, key_sum[i])
		}
		for i:=0;i<(sha256.BlockSize-len(key_sum));i++ {
			hmac_key = append(hmac_key, byte(0x00))
		}
	}

	k_ipad := block_exor(ipad, hmac_key)
	k_ipad = append(k_ipad, data...)

	hash_k_ipad := sha256.Sum256(k_ipad)

	k_opad := block_exor(opad, hmac_key)
	for i:=0;i<len(hash_k_ipad);i++ {
		k_opad = append(k_opad, hash_k_ipad[i])
	}

	hmac := sha256.Sum256(k_opad)

	return hmac
}

func check_mac(data, data_hmac, sign_key []byte) string {

	hmac := calc_hmac(data, sign_key)

	if len(hmac) != len(data_hmac) {
		return "INVALID MAC"
	}
	for i:=0;i<len(hmac);i++ {
		if data_hmac[i] != hmac[i] {
			return "INVALID MAC"
		}
	}

	return "SUCCESS"
}

func flagParse(args []string) string {

	var InputFile string

	if len(args) < 3 {
		show_usage()
		os.Exit(0)
	}
	if strings.Compare(args[1],"-i") == 0 {
		InputFile = args[2]
	} else {
		show_usage()
		os.Exit(0)
	}

	return InputFile
}

func aes_auth_decrypt(ciphertext, key []byte) (string, []byte) {

	var plaintext []byte
	pt := make([]byte, aes.BlockSize)
	iv := make([]byte, aes.BlockSize)

	dec_key := key[0:aes.BlockSize]
	sign_key := key[aes.BlockSize:len(key)]

	iv = ciphertext[0:aes.BlockSize]
	ecb_cipher, err := aes.NewCipher(dec_key)
	check(err)
	blocks := (len(ciphertext)/aes.BlockSize)

	for i:=1;i<blocks;i++ {

		curr_block := ciphertext[(i*aes.BlockSize):(i+1)*aes.BlockSize]
		ecb_cipher.Decrypt(pt, curr_block)
		temp := block_exor(pt, iv)
		iv = curr_block

		plaintext = append(plaintext, temp...)
	}

	unpadded_pt := remove_pad(plaintext)
	if strings.Compare(string(unpadded_pt), "INVALID PADDING")==0 {
		exit_code := "INVALID PADDING"
		return exit_code, plaintext
	}
	data_hmac := unpadded_pt[(len(unpadded_pt)-sha256.Size):]
	real_pt := unpadded_pt[0:(len(unpadded_pt)-sha256.Size)]

	exit_code := check_mac(real_pt, data_hmac, sign_key)
	return exit_code, plaintext
}


func main() () {

	file := flagParse(os.Args)
	data, err := ioutil.ReadFile(file)
	check(err)

	//hardcoded key: AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA
	exit_code, _ := aes_auth_decrypt(data, []byte{170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170})

	fmt.Printf("%s", exit_code)
}
