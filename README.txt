Usage :

1. Build the program - go build encrypt-auth.go

2. Use below format to process encrypt/decrypt

./encrypt-auth <mode> -k <32 byte key> -i <input-file> -o <output-file>

 where <mode> - encrypt (or) decrypt

 <32 byte key> - The program would use the first 16 bytes as the AES key and next 16 bytes as the HMAC key. The input for this key should be a 64 character Hexadecimal string
 <input-file> - If the mode is encrypt, the input-file should be the plaintext file_name. If the mode is decrypt, the input-file should bethe ciphertext file_name
 <output-file> - If the mode is encrypt, the output-file should be the name of the ciphertext file to which encrypted output is required to be stored.If the mode is decrypt, the output-file should be the name of the plaintext file to which the decrypted output (recovered plaintext) is to be stored

3. Output is written a string typecast of the byte array to a file.

4. Handles all types of test cases.
  - Invalid padding
  - Invalid MAC
  - Invalid key length
  - Files not having right access permission
  - Requested Mode is wrong
  - Large Files
  -Ciphertext not a multiple of AES Blocksize.

5. Protocol follows authenticated encryption. AES-CBC mode is used for encryption and HMACSHA256 is used for authentication.

6. HMAC Tags are computed as per the RFC 4634

7. AES Key size - 16 bytes , HMAC Key size - 16 bytes, AES Blocksize - 16 bytes, HMACSHA256 Tag size - 32 bytes

License :

Venkatesh Gopal (vgopal3@jhu.edu. vnktshgopalg@gmail.com)
