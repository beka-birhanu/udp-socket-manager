# **UDP Socket Manager**  

## **Overview**  

UDP-based Socket Manager for secure communication using asymmetric and symmetric encryption is a wrapper over UDP. It uses Protocol Buffers for message encoding and supports DTLS for secure communication.  

## **How It Works**  

1. **Client Fetches Server Public Key** – The client retrieves the server’s public key.  
2. **Client Hello** – The client sends a `hello` message containing a random value and an AES-CBC key, encrypted with the server’s public key.  
3. **Server Hello Verify** – The server responds with a `helloverify` message containing a cookie HMAC, using the AES-CBC key from the client.  
4. **Client Verification** – The client resends the `hello` message with the cookie HMAC, AES-CBC key, and a verification token.  
5. **Server Hello** – The server completes the handshake by sending a session ID.  
6. **Session Maintenance** – The client continues communication while maintaining heartbeat messages; otherwise, the session expires.  

## **Message Structure**  

| Field          | Description             |  
|---------------|-------------------------|  
| Message Type  | 1 byte                   |  
| Payload       | ... rest of the message  |  

### **Message Types**  

```plaintext
    ClientHelloRecordType   = 1  
    HelloVerifyRecordType   = 2  
    ServerHelloRecordType   = 3  
    PingRecordType          = 4  
    PongRecordType          = 5  
    UnAuthenticated         = 6  
```
Any value greater than these can be used as a custom message type.  

## Docs
[Socket Client docs](./docs/socket-client.md)
[Socket Server docs](./docs/socket-server.md)

