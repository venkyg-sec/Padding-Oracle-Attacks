// Copyright 2017 Venkatesh Gopal. All rights reserved.
// Use of this code is governed by Venkatesh Gopal
// Any modification and redistribution are to be notified to Venkatesh Gopal
// vgopal3@jhu.edu, vnktshgopalg@gmail.com

package main

import (
  "fmt"
  "crypto/sha256"
  "crypto/rand"
  "crypto/aes"
  "io/ioutil"
  "encoding/hex"
  "os"
)

func main() {

  if(len(os.Args) != 8 || os.Args[1] == "-h" || os.Args[1] == "--help") {
    //Below case to handle invalid inputs
      handleInvalidCommandLineInputs()

  } else {

    // Case where the input matches the specification

  file_name := os.Args[5]
  fileContent, err_data_file := ioutil.ReadFile(file_name)

  /* Error handling if file wasn't opened successfully */
  if (err_data_file != nil) {
    fmt.Println("\nError Opening Input file \n" +
      "Reason - File doesn't exist (or) doesn't"+
    " hold right permission to read \n")
  } else {

  if (len(os.Args[3]) != 64) {
    fmt.Println("\n Error parsing the key (Not a 64 character Hexadecimal)")
  } else {
  Key := os.Args[3]
  hexAesKey := Key[0:32]

  iv := make([]byte,16)
  _, err := rand.Read(iv)
  if err != nil {
    fmt.Println(" Error generating a pseudo Random number")
  }


  operation := os.Args[1] // Should be encrypt or decrypt
  outputFileName := os.Args[7]
  hexAesKeyBytes, _ := hex.DecodeString(hexAesKey)


  hexHmacKey := Key[32:64]
  hexHmacKeyBytes, _ := hex.DecodeString(hexHmacKey)

  if operation == "encrypt" {

    encryptionAesCBC(iv, fileContent , hexAesKeyBytes,hexHmacKeyBytes, outputFileName)
  } else if operation == "decrypt" {
    decryptionAesCBC(fileContent, hexAesKeyBytes, hexHmacKeyBytes, outputFileName)
  } else {
    handleInvalidCommandLineInputs()
    }

  }
  }
 }
}


/* Function to XOR 2 Byte Arrays */
func XorBytes(ivPlaintext, iv, plaintext []byte) int {

	ivLength := len(iv)
  if len(plaintext) < ivLength {
    ivLength = len(plaintext)

	}

	for i := 0; i < ivLength; i++ {
    ivPlaintext[i] = iv[i] ^ plaintext[i]
  }
  return ivLength
}

func encryptionAesCBC(iv []byte, plaintext []byte, hexAesKeyBytes []byte, hexHmacKeyBytes []byte, cipherTextFile string) {

  cipher_block, error_block := aes.NewCipher(hexAesKeyBytes)
  hmac := hmacSha256(plaintext, hexHmacKeyBytes)

  ivPlaintext := make([]byte, 16)


  if (error_block != nil) {
    fmt.Println("Key size error")
    }

    for i:= 0; i < len(hmac); i++ {

      plaintext = append(plaintext, hmac[i])
    }


  aesBlocksize := 16
  if len(plaintext) < 16 {
    residue := 16 - len(plaintext)
    for i := 0; i < residue; i++ {
      plaintext = append(plaintext, byte(residue))

    }
    numberOfBytes := XorBytes(ivPlaintext, iv, plaintext)

    if (numberOfBytes == 0) {
      fmt.Println("\n XOR Error")
    }
    cipherText := make([]byte, aes.BlockSize)

    cipher_block.Encrypt(cipherText,ivPlaintext)
    fmt.Println(string(cipherText))

  } else if (len(plaintext) >= 16) {
    multipleVal := (len(plaintext)) / 16

    residue := 0
    if (len(plaintext) % 16 == 0) {
      residue = 16
    } else {
    residue = ((multipleVal + 1) * 16 ) - len(plaintext)
    }
    for i:=0 ; i < residue ; i++ {
      plaintext = append(plaintext, byte(residue))
    }

    ivBlock1 := iv
    numberOfBytes := XorBytes(ivPlaintext, ivBlock1, plaintext[0:aesBlocksize])
    if (numberOfBytes == 0) {
      fmt.Println("\n XOR Error")
    }

    cipherText := make([]byte, aesBlocksize * (multipleVal + 1))


    cipher_block.Encrypt(cipherText[0:aesBlocksize],ivPlaintext)


    for i := 1; i <= multipleVal ; i++ {


      numberOfBytes := XorBytes(ivPlaintext,
      cipherText[((i -1)* aesBlocksize):(i * aesBlocksize)],
      plaintext[(aesBlocksize * i):(aesBlocksize* (i+1))])
      if (numberOfBytes == 0) {
        fmt.Println("\n XOR Error")
      }


      cipher_block.Encrypt(cipherText[(i*aesBlocksize):((i+1)*aesBlocksize)],
      ivPlaintext)

    }


    ivCiphertextConcatenated := make([]byte, len(iv) + len(cipherText))
    ivCiphertextConcatenated = iv


    for i := 0; i < len(cipherText); i++ {
      ivCiphertextConcatenated = append(ivCiphertextConcatenated,
      cipherText[i])
    }



    err := ioutil.WriteFile(cipherTextFile, ivCiphertextConcatenated, 0644)
    if err != nil {
      fmt.Println("Error opening file")
    }
  }


}

func decryptionAesCBC(ivCiphertextConcatenated []byte, hexAesKeyBytes []byte,  hexHmacKeyBytes []byte, recoveredPlaintextFile string) {

  cipher_block, error_block := aes.NewCipher(hexAesKeyBytes)

  ivLength := 16
  iv := ivCiphertextConcatenated[:ivLength]

  ciphertext := make([]byte, len(ivCiphertextConcatenated) - 16)
  ciphertext = ivCiphertextConcatenated[ivLength:len(ivCiphertextConcatenated)]


  if (error_block != nil) {
    fmt.Println("Key size error")
    }

  aesBlocksize := 16


  if (len(ciphertext) % aesBlocksize != 0) {

    fmt.Println("\nError during transmission. Ciphertext is not a multiple of" +
       "BlockSize ")

  } else {
  // For handling case where size of ciphertext is same as blocksize
  if len(ciphertext) == 16 {
  plaintext := make([]byte, aesBlocksize)
  ivBlock1 := iv
  cipher_block.Decrypt(plaintext[:aesBlocksize],ciphertext[:aesBlocksize])
  numberOfBytes := XorBytes(plaintext[:aesBlocksize],
    ivBlock1, plaintext[:aesBlocksize])
  if (numberOfBytes == 0) {
    fmt.Println("\n XOR Error")
  }

  }



  if len(ciphertext) > 16 {

    multipleVal := len(ciphertext) / 16
    plaintext :=  make([]byte, aesBlocksize * multipleVal)

    // For handling first block
    ivBlock1 := iv
    cipher_block.Decrypt(plaintext[:aesBlocksize],ciphertext[:aesBlocksize])
    numberOfBytes := XorBytes(plaintext[:aesBlocksize],
      ivBlock1, plaintext[:aesBlocksize])

    if (numberOfBytes == 0) {
      fmt.Println("\n XOR Error")
    }


    // For handling rest of the blocks

    for i := 1; i < multipleVal; i++ {

          cipher_block.Decrypt(plaintext[(aesBlocksize * i):(aesBlocksize  * (i + 1))],
          ciphertext[(aesBlocksize * i):(aesBlocksize * (i+1))])

          // Xor the output of decryption with the IV

          numberOfBytes = XorBytes(plaintext[(aesBlocksize * i):(aesBlocksize *(i + 1))],
          ciphertext[(aesBlocksize * (i -1)): (aesBlocksize * i)] ,
          plaintext[(aesBlocksize * i):(aesBlocksize  *(i + 1))] )

        }


    paddingByte := plaintext[(multipleVal * aesBlocksize) - 1]
    //fmt.Println("Padding byte is ", paddingByte)
    paddingbyteInteger := (int)(paddingByte)
    //fmt.Println("Padding byte in Integer is ", paddingbyteInteger)
    paddingBool := true
    for i:=1; i <= paddingbyteInteger; i++ {

      if (plaintext[(multipleVal * aesBlocksize) - i] != paddingByte) {
            paddingBool = false
            fmt.Println("INVALID PADDING")
            break
      }
    }

    if (paddingBool) {
    fmt.Println("Plaintext is ", plaintext)
    plaintext = plaintext[:((multipleVal * aesBlocksize) - (int)(paddingByte))]


    // Removing tag from the recovered plaintext
    tagRetrieved := plaintext[(len(plaintext) - 32):len(plaintext)]
    recoveredMessage := plaintext[:(len(plaintext)- 32)]

    // Computer HMAC on the recovered Message
    TagOnRecoveredMessage := hmacSha256(recoveredMessage,hexHmacKeyBytes)



    boolVerificationHMAC := false

    for i := 0; i < 32; i++ {
      if(tagRetrieved[i] != TagOnRecoveredMessage[i]) {
        boolVerificationHMAC = false
        break;
    } else {
      boolVerificationHMAC = true
    }

  }

    if (boolVerificationHMAC) {

      err := ioutil.WriteFile(recoveredPlaintextFile, recoveredMessage, 0644)
      fmt.Println("Decryption success")
      if err != nil {
        fmt.Println("Error opening file")
      }
    } else {
      fmt.Println("INVALID MAC")
    }


  }
 }

}
}


func hmacSha256(Message []byte, hexHmacKeyBytes []byte) ([32]byte) {

  // As per HMAC specification, keys greater than the BlockSize are to be
  // shortened to 64 bytes
  hmacSHA256BlockSize := 64
  key := make([]byte,hmacSHA256BlockSize )
  if (len(hexHmacKeyBytes) > hmacSHA256BlockSize) {
    // TODO Some problem with below key (unable to take as a byte array - DEBUG)
    key := sha256.Sum256(hexHmacKeyBytes)
    fmt.Println(key)
  }

  if (len(hexHmacKeyBytes) < hmacSHA256BlockSize) {
    lengthDifference := hmacSHA256BlockSize - len(hexHmacKeyBytes)
    padZeroByte := make([]byte, lengthDifference)
    key := hexHmacKeyBytes


    for i := 0; i < lengthDifference; i++ {
      padZeroByte[i] = 0x00
      key = append(key,padZeroByte[i])
    }




  }

  opadRep := make([]byte, 64)
  for i := 0; i < 64; i++ {
    opadRep[i] = 0x5c
  }


  ipadRep := make([]byte, 64)
  for i := 0; i < 64; i++ {
    ipadRep[i] = 0x36
  }


  xorOPadKey := make([]byte, 64)
  xorIPadKey := make([]byte, 64)
  xorOPadKeyLength := XorBytes(xorOPadKey, opadRep, key)
  xorIPadKeyLength := XorBytes(xorIPadKey, ipadRep, key)

  if (xorOPadKeyLength == 0) || (xorIPadKeyLength == 0) {
    fmt.Println("XOR failed")
  }

  iKeyPadMessageConcatenated := make([]byte, xorIPadKeyLength + len(Message))
  iKeyPadMessageConcatenated = xorIPadKey
  for i:=0 ; i < len(Message); i++ {
    iKeyPadMessageConcatenated = append(iKeyPadMessageConcatenated, Message[i])
  }

  hasiKeyPadMessageConcatenated := sha256.Sum256(iKeyPadMessageConcatenated)

  oKeyPadhasiKeyPadMessageConcatenated := make([]byte, xorOPadKeyLength + len(hasiKeyPadMessageConcatenated))
  oKeyPadhasiKeyPadMessageConcatenated = xorOPadKey
  for i := 0; i < len(hasiKeyPadMessageConcatenated); i++ {
    oKeyPadhasiKeyPadMessageConcatenated = append(oKeyPadhasiKeyPadMessageConcatenated,hasiKeyPadMessageConcatenated[i])
  }

  hashoKeyPadhasiKeyPadMessageConcatenated := sha256.Sum256(oKeyPadhasiKeyPadMessageConcatenated)

  return hashoKeyPadhasiKeyPadMessageConcatenated



}


func handleInvalidCommandLineInputs() {

  fmt.Println("Invalid Input, follow Command Line Specification \n\n" +
    "./encrypt-auth <mode> -k <32 byte key> -i <input-file> -o " +
    "<output-file>\n\n where <mode> - encrypt (or) decrypt \n " +
    "<32 byte key> - The program would use the first 16 bytes as the AES " +
    "key and next 16 bytes as the HMAC key. The input for this key should " +
    "be a 64 character Hexadecimal string\n " +
    "<input-file> - If the mode is encrypt, the input-file should be the " +
    "plaintext file_name. If the mode is decrypt, the input-file should be" +
    "the ciphertext file_name\n " +
    "<output-file> - If the mode is encrypt, the output-file should be" +
    " the name of the ciphertext file to which encrypted output is required" +
    " to be stored.If the mode is decrypt, the output-file should be the " +
    "name of the plaintext file to which the decrypted output " +
    "(recovered plaintext) is to be stored \n")
}
