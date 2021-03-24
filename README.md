# GCMEncryption
GCM Encryption with no padding, PDFK2
Need of doing the GCM Encryption - Send the encrypted parameters to the server for security.
Generate 12 bytes iv i.e. nonce.
Generate 16 bytes random salt.
With the help of password and salt, generate AES Key.
Generate cipher text with aes key, genrated iv and plain text that you want to encrypt.
Generate cipher salt with salt,iv and generated cipher text.
Do base64 encoding with cipher salt and send it in the request httpBody.
Finally will get the data in the response.
Convert it into string then deocde the string to the decrypted data.
Derypt the data with the help of cipher text, iv and salt used in encrypting the data.
