# **UDP Client Socket Manager**  

## **Overview**  

 A UDP-based client for secure communication using asymmetric and symmetric encryption. It establishes a connection with a UDP server, performs a DTLS-like handshake, maintains a session, and sends periodic ping requests to keep the connection alive.  

## **Usage**  

```go
serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:8080")

clientConfig := udp.ClientConfig{
    ServerAddr:         serverAddr,
    Encoder:            myEncoder,  // Implements socket_i.SocketEncoder
    AsymmCrypto:        myAsymmCrypto,  // Implements socket_i.Asymmetric
    ServerAsymmPubKey:  serverPublicKey,
    SymmCrypto:         mySymmCrypto,  // Implements socket_i.Symmetric
    ClientSymmKey:      clientKey,
    AuthToken:          authToken,
    OnConnectionSucces: func() { fmt.Println("Connected successfully") },
    OnServerResponse:   func(t byte, data []byte) { fmt.Println("Received:", t, data) },
    OnPingResult:       func(ms int64) { fmt.Println("Ping:", ms, "ms") },
    Logger:             myLogger,  // Implements general_i.Logger
}

client, err := udp.NewClientServerManager(clientConfig, udp.ClientWithReadBufferSize(4096))
if err != nil {
    log.Fatal(err)
}

err = client.Connect()
if err != nil {
    log.Fatal(err)
}
```

### **Disconnecting the Client**  

```go
client.Disconnect()
```

### **Sending a Custom Message**  

```go
err := client.SendToServer(10, []byte("Hello Server"))
if err != nil {
    log.Println("Failed to send:", err)
}
```

## Options

### **ClientWithReadBufferSize**  

```go
func ClientWithReadBufferSize(bs int) ClientOption
```

Sets the read buffer size for incoming messages.  

#### **Parameters:**  

- `bs int`: Buffer size in bytes.  

#### **Returns:**  

- `ClientOption`: A function to configure the client.  

---

### **ClientWithPingInterval**  

```go
func ClientWithPingInterval(d time.Duration) ClientOption
```

Sets the interval for sending ping messages.  

#### **Parameters:**  

- `d time.Duration`: The interval duration.  

#### **Returns:**  

- `ClientOption`: A function to configure the client.  

---

### **ClientWithLogger**  

```go
func ClientWithLogger(l general_i.Logger) ClientOption
```

Sets the logger instance.  
