# Secure transport protocol
Secure transport protocol project aims to guarantee secure communication at the transport level (in this case UDP) by extending the socket interface, introducing confidentiality in communication. To derive the encryption key (and the authentication key, if supported) a symmetric key is used to ensure secure communication between two parties exchanging data with each other.

**PROJECT DETAILS:**
**• Server:** contains details about the exchange of the key and messages with the client
**• Client:** contains details about the exchange of the key and messages with the server
**• DatagramSocketEncrypt:** represents the extension of the DatabramSocket class and contains
the details of the encryption algorithm used to encrypt the messages exchanged between
client and server.
**• Utils**
**Step 1:** Key exchange
In the first part of the program the key is exchanged using the Diffie-Hellman algorithm. In particular, in the Client class two integers p and g are generated as BigInteger and are sent to the server without any type of encryption using a datagam socket. The server receives the data and generates its own pair of keys (public and private) using appropriate Java libraries that support encryption and sends its public key to the client. The client in turn generates its own key pair, sends its public key to the server and, using the received server's public key, calculates the shared secret key Kab. Similarly the server, received the client's public key calculates the shared secret key.
**Step 2:** Exchange encrypted messages
In the second part of the program the client reads the message from the file message.txt and calls the secureSend encryption function contained in the DatagramSocketEncrypt class to encrypt the message. The server receives the message from the client and decrypts it using the secureReceive decryption method, also implemented in the DatagramSocketEncrypt class. In the same way the server criticizes a message contained in message2.txt and the client decrypts it.
The DatagramSocketEncrypt class contains the two methods mentioned above.
**• secureSend:** receives the secret key as input, the message as byte array, the address
ip and the port. The message is encrypted using AES, with CBC and padding PKCS5. The initialization vector is static and defined outside the method. The encrypted message
it is then sent using the send. The method returns an array of bytes representing the
ciphertext.
**• secureReceive:** receives only the secret key, receives the package and it
deciphered using AES, with CBC and padding PKCS5. The method returns an array of bytes that
matches the full text.
Since the methods return byte arrays in Client and Server (after calling the secureReceive method) it is necessary to convert the messages into strings.     
