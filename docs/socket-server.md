# UDP ServerSocketManager

## Overview

`ServerSocketManager` is a UDP-based socket manager that accepts client connections, Performs the DTLS handshake and processes client requests after authentication.

### `ServerConfig`
Holds the necessary parameters for initializing a `ServerSocketManager`.

```go
type ServerConfig struct {
    ListenAddr    *net.UDPAddr
    Authenticator socket_i.Authenticator
    AsymmCrypto   socket_i.Asymmetric
    SymmCrypto    socket_i.Symmetric
    Encoder       socket_i.SocketEncoder
    HMAC          socket_i.HMAC
    Logger        general_i.Logger
}
```

## Methods

### `NewServerSocketManager`
Initializes a new `ServerSocketManager` with the given configuration and options.

```go
func NewServerSocketManager(c ServerConfig, options ...ServerOption) (*ServerSocketManager, error)
```

### `Serve`
Starts listening to the UDP port for incoming bytes and processes client requests.

```go
func (s *ServerSocketManager) Serve()
```

### `Stop`
Gracefully stops the UDP server.

```go
func (s *ServerSocketManager) Stop()
```


### `BroadcastToClients`
Broadcasts messages to multiple clients.

```go
func (s *ServerSocketManager) BroadcastToClients(clientIDs []uuid.UUID, typ byte, payload []byte)
```
# ServerSocketManager Configuration Options

`ServerSocketManager` can be customized using functional options. Below are the available options:

## `ServerWithClientRegisterHandler`
Registers a callback function that executes when a new client registers.

```go
udp.ServerWithClientRegisterHandler(func(u uuid.UUID) {
    fmt.Printf("\nUser %s registered", u)
})
```

- **Parameter**: `func(uuid.UUID)` – A function that receives the client's UUID.  
- **Usage**: Typically used for logging or tracking active users.

---

## `ServerWithReadBufferSize`
Sets the read buffer size for incoming UDP packets.

```go
udp.ServerWithReadBufferSize(2048)
```

- **Parameter**: `size int` – Buffer size in bytes.  
- **Default**: Implementation-dependent.  
- **Usage**: Adjust based on expected packet size to optimize performance.

---

## `ServerWithHeartbeatExpiration`
Defines the duration after which a client is considered inactive if no heartbeat is received.

```go
udp.ServerWithHeartbeatExpiration(time.Second * 5)
```

- **Parameter**: `duration time.Duration` – Timeout duration.  
- **Usage**: Helps manage client connections and detect disconnections.

