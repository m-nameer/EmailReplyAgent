package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "os/signal"
    "sync"
    "syscall"
    "time"

    "github.com/gorilla/mux"
    "github.com/gorilla/websocket"
    "go.mau.fi/whatsmeow"
    waProto "go.mau.fi/whatsmeow/binary/proto"
    "go.mau.fi/whatsmeow/store/sqlstore"
    "go.mau.fi/whatsmeow/types"
    "go.mau.fi/whatsmeow/types/events"
    waLog "go.mau.fi/whatsmeow/util/log"
    "google.golang.org/protobuf/proto"
    _ "github.com/mattn/go-sqlite3"
	"strings"
    store "go.mau.fi/whatsmeow/store"
    // "github.com/google/uuid"
)

 


var storeContainer *sqlstore.Container

type WhatsAppClient struct {
    Client       *whatsmeow.Client
    eventHandler *waHandler
    JID          string
}

type waHandler struct {
    userID       string
    messageQueue chan *MessageEvent
}

func (h *waHandler) HandleEvent(evt interface{}) {
    switch v := evt.(type) {
    case *events.Message:


        
        if v.Info.MessageSource.IsGroup {
            // log.Printf("🔕 Ignoring group message from %s", v.Info.Sender.String())
            return
        }


        senderJID := v.Info.Sender.String()
        recipientJID := v.Info.Chat.String()

        // Only process messages where sender == recipient (i.e. user messaging themselves)
        if senderJID != recipientJID {
            // log.Printf("🔕 Ignoring message not sent to self. Sender: %s, Recipient: %s", senderJID, recipientJID)
            return
        }
        // Create message event
        msgEvent := &MessageEvent{
            UserID:      h.userID,
            Timestamp:   time.Now(),
            FromMe:      v.Info.IsFromMe,
            SenderJID:   v.Info.Sender.String(),
        }


        // Extract the message content based on type
        if v.Message == nil {
            // log.Printf("Received message with nil content from %s", v.Info.Sender)
            msgEvent.MessageType = "unknown"
            msgEvent.Content = "empty message"
        } else if text := v.Message.GetConversation(); text != "" {
            // Plain text message
            msgEvent.MessageType = "text"
            msgEvent.Content = text
            // log.Printf("Received text message: %s", text)
        } else if extendedText := v.Message.GetExtendedTextMessage(); extendedText != nil {
            // Extended text message (often with formatting or links)
            msgEvent.MessageType = "text"
            msgEvent.Content = extendedText.GetText()
            // log.Printf("Received extended text message: %s", extendedText.GetText())
        } else if imageMsg := v.Message.GetImageMessage(); imageMsg != nil {
            // Image message
            msgEvent.MessageType = "image"
            msgEvent.Content = "📷 Image message"
            // log.Printf("Received image message")
        } else if videoMsg := v.Message.GetVideoMessage(); videoMsg != nil {
            // Video message
            msgEvent.MessageType = "video"
            msgEvent.Content = "🎥 Video message"
            log.Printf("Received video message")
        } else if audioMsg := v.Message.GetAudioMessage(); audioMsg != nil {
            // Audio message
            msgEvent.MessageType = "audio"
            msgEvent.Content = "🔊 Audio message"
            // log.Printf("Received audio message")
        } else if docMsg := v.Message.GetDocumentMessage(); docMsg != nil {
            // Document message
            msgEvent.MessageType = "document"
            docName := docMsg.GetFileName()
            if docName == "" {
                docName = "file"
            }
            msgEvent.Content = "📄 Document: " + docName
            // log.Printf("Received document: %s", docName)
        } else if contactMsg := v.Message.GetContactMessage(); contactMsg != nil {
            // Contact message
            msgEvent.MessageType = "contact"
            msgEvent.Content = "👤 Contact card"
            // log.Printf("Received contact card")
        } else if locationMsg := v.Message.GetLocationMessage(); locationMsg != nil {
            // Location message
            msgEvent.MessageType = "location"
            msgEvent.Content = "📍 Location: " + fmt.Sprintf("%.6f,%.6f", locationMsg.GetDegreesLatitude(), locationMsg.GetDegreesLongitude())
            // log.Printf("Received location message")
        } else if stickerMsg := v.Message.GetStickerMessage(); stickerMsg != nil {
            // Sticker message
            msgEvent.MessageType = "sticker"
            msgEvent.Content = "😊 Sticker"
            // log.Printf("Received sticker")
        } else if reactionMsg := v.Message.GetReactionMessage(); reactionMsg != nil {
            // Reaction to a message
            msgEvent.MessageType = "reaction"
            msgEvent.Content = "👍 Reaction: " + reactionMsg.GetText()
            // log.Printf("Received reaction: %s", reactionMsg.GetText())
        } else if buttonsResponseMsg := v.Message.GetButtonsResponseMessage(); buttonsResponseMsg != nil {
            // Button response
            msgEvent.MessageType = "button_response"
            msgEvent.Content = "Button: " + buttonsResponseMsg.GetSelectedButtonID()
            // log.Printf("Received button response: %s", buttonsResponseMsg.GetSelectedButtonID())
        } else {
            // Unknown message type
            msgEvent.MessageType = "unknown"
            msgEvent.Content = "Message of unsupported type"
            // log.Printf("Received message of unknown type from %s", v.Info.Sender)
        }

        // Send to queue for processing
        h.messageQueue <- msgEvent
    
    case *events.Connected:
        log.Printf("WhatsApp client connected for user %s", h.userID)
    
    case *events.Disconnected:
        log.Printf("WhatsApp client disconnected for user %s", h.userID)
    }
}

type MessageEvent struct {
    UserID      string    `json:"user_id"`
    Timestamp   time.Time `json:"timestamp"`
    FromMe      bool      `json:"from_me"`
    MessageType string    `json:"message_type"` // text, audio, etc.
    Content     string    `json:"content"`      // text content or media URL
    SenderJID   string    `json:"sender_jid"`
}

var (
    clientsLock sync.RWMutex
    clients     = make(map[string]*WhatsAppClient)
    wsUpgrader  = websocket.Upgrader{
        CheckOrigin: func(r *http.Request) bool {
            return true
        },
    }
    // Global message broker
    messageBroker = NewMessageBroker()
)

// MessageBroker manages subscribers for each user
type MessageBroker struct {
    subscribers     map[string][]chan *MessageEvent
    subscribersLock sync.RWMutex
}

func NewMessageBroker() *MessageBroker {
    return &MessageBroker{
        subscribers: make(map[string][]chan *MessageEvent),
    }
}

func (mb *MessageBroker) Subscribe(userID string) chan *MessageEvent {
    ch := make(chan *MessageEvent, 100)
    
    mb.subscribersLock.Lock()
    defer mb.subscribersLock.Unlock()
    
    if _, exists := mb.subscribers[userID]; !exists {
        mb.subscribers[userID] = []chan *MessageEvent{}
    }
    
    mb.subscribers[userID] = append(mb.subscribers[userID], ch)
    return ch
}

func (mb *MessageBroker) Unsubscribe(userID string, ch chan *MessageEvent) {
    mb.subscribersLock.Lock()
    defer mb.subscribersLock.Unlock()
    
    if subs, exists := mb.subscribers[userID]; exists {
        for i, sub := range subs {
            if sub == ch {
                mb.subscribers[userID] = append(subs[:i], subs[i+1:]...)
                close(ch)
                break
            }
        }
    }
}

func (mb *MessageBroker) Publish(event *MessageEvent) {
    mb.subscribersLock.RLock()
    defer mb.subscribersLock.RUnlock()
    
    if subs, exists := mb.subscribers[event.UserID]; exists {
        for _, ch := range subs {
            // Non-blocking send
            select {
            case ch <- event:
                // Message sent successfully
            default:
                // Channel buffer full, log and continue
                log.Printf("Warning: Buffer full for subscriber of user %s", event.UserID)
            }
        }
    }
}

func startWhatsAppClient(userID string, messageQueue chan *MessageEvent) (*WhatsAppClient, error) {
    // dbPath := fmt.Sprintf("./whatsmeow-%s.db", userID)
    // ctx := context.Background()
    
    // Set up database connection with context
    // container, err := sqlstore.New(ctx, "sqlite3", fmt.Sprintf("file:%s?_foreign_keys=on", dbPath), waLog.Stdout("database", "DEBUG", false))
    // if err != nil {
    //     return nil, fmt.Errorf("failed to connect to database: %v", err)
    // }
    
    // Get device store with context
    // deviceStore, err := container.GetFirstDevice(ctx)
    // if err != nil {
    //     deviceStore = container.NewDevice()
    // }

    ctx := context.Background()

    if storeContainer == nil {
        return nil, fmt.Errorf("shared store container not initialized")
    }


    // deviceStore, err := storeContainer.GetFirstDevice(ctx)
    // if err != nil || deviceStore == nil {
    //     log.Printf("Device not found in shared DB. Creating new device for user %s", userID)
    //     deviceStore = storeContainer.NewDevice()
    // }

    devices, err := storeContainer.GetAllDevices(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to list devices: %v", err)
    }

    var selectedDevice *store.Device

    for _, dev := range devices {
        if dev.ID.User == userID {
            selectedDevice = dev
            break
        }
    }

    // 🔧 If not found, create a new one
    if selectedDevice == nil {
        log.Printf("Creating new device for user: %s", userID)
     
        selectedDevice = storeContainer.NewDevice()
     
        selectedDevice.PushName = userID
    }
    
    client := whatsmeow.NewClient(selectedDevice, waLog.Stdout("whatsapp", "DEBUG", false))
    handler := &waHandler{userID: userID, messageQueue: messageQueue}

    client.AddEventHandler(handler.HandleEvent)
    
   
    return &WhatsAppClient{
        Client:       client,
        eventHandler: handler,
    }, nil
}


func qrCodeHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    userID := vars["userId"]

    clientsLock.RLock()
    waClient, exists := clients[userID]
    clientsLock.RUnlock()

    if !exists {
        messageQueue := make(chan *MessageEvent, 100)
        var err error
        waClient, err = startWhatsAppClient(userID, messageQueue)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to create WhatsApp client: %v", err), http.StatusInternalServerError)
            return
        }

        clientsLock.Lock()
        clients[userID] = waClient
        clientsLock.Unlock()

        go processMessages(messageQueue)
    }

    if waClient.Client == nil {
        http.Error(w, "WhatsApp client not initialized", http.StatusInternalServerError)
        return
    }

    if waClient.Client.IsConnected() {
        if waClient.JID == "" && waClient.Client.Store.ID != nil {
            waClient.JID = waClient.Client.Store.ID.User + "@s.whatsapp.net"
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "status":  "connected",
            "user_id": userID,
            "jid":     waClient.JID,
        })
        return
    }

    qrChan, err := waClient.Client.GetQRChannel(context.Background())
    if err != nil {
        http.Error(w, fmt.Sprintf("Failed to get QR channel: %v", err), http.StatusInternalServerError)
        return
    }
    if qrChan == nil {
        http.Error(w, "QR channel is nil", http.StatusInternalServerError)
        return
    }

    err = waClient.Client.Connect()
    if err != nil {
        http.Error(w, fmt.Sprintf("Failed to connect: %v", err), http.StatusInternalServerError)
        return
    }

    select {
    case qr, ok := <-qrChan:
        if !ok || qr.Code == "" {
            http.Error(w, "Failed to receive QR code", http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "status": "need_scan",
            "qr":     qr.Code,
        })

        go func() {
            for {
                select {
                case evt, ok := <-qrChan:
                    if !ok {
                        return
                    }
                    switch evt.Event {
                    case "success":
                        if waClient.Client.Store.ID != nil {
                            waClient.JID = waClient.Client.Store.ID.User + "@s.whatsapp.net"
                            log.Printf("✅ User %s connected as %s", userID, waClient.JID)
                        } else {
                            log.Printf("⚠️ Connected but no JID found for user %s", userID)
                        }
                        return
                    case "timeout", "cancelled":
                        log.Printf("❌ QR expired or cancelled for user %s", userID)
                        waClient.Client.Disconnect()
                        return
                    }
                case <-time.After(20 * time.Minute):
                    log.Printf("⏰ QR scan timeout for user %s", userID)
                    waClient.Client.Disconnect()
                    return
                }
            }
        }()

    case <-time.After(15 * time.Second):
        http.Error(w, "Timeout waiting for QR code", http.StatusGatewayTimeout)
    }
}





func disconnectHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    userID := vars["userId"]

    clientsLock.Lock()
    defer clientsLock.Unlock()

    waClient, exists := clients[userID]
    if exists && waClient.Client != nil {
        waClient.Client.Disconnect()
        delete(clients, userID)
        log.Printf("🔌 Disconnected WhatsApp for user: %s", userID)
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "status": "disconnected",
    })
}


func messageStreamHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    userID := vars["userId"]
    
    clientsLock.RLock()
    waClient, exists := clients[userID]
    clientsLock.RUnlock()
    
    if !exists || !waClient.Client.IsConnected() {
        http.Error(w, "WhatsApp client not connected", http.StatusBadRequest)
        return
    }
    
    // Upgrade to WebSocket
    conn, err := wsUpgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Printf("Failed to upgrade to WebSocket: %v", err)
        return
    }
    defer conn.Close()
    
    // Subscribe to user's messages
    ch := messageBroker.Subscribe(userID)
    defer messageBroker.Unsubscribe(userID, ch)
    
    // Send ping messages to keep connection alive
    go func() {
        ticker := time.NewTicker(30 * time.Second)
        defer ticker.Stop()
        
        for {
            select {
            case <-ticker.C:
                if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
                    return
                }
            case <-r.Context().Done():
                return
            }
        }
    }()
    
    // Handle incoming messages
    for {
        select {
        case msg, ok := <-ch:
            if !ok {
                return
            }
            
            err := conn.WriteJSON(msg)
            if err != nil {
                log.Printf("WebSocket write error: %v", err)
                return
            }
            
        case <-r.Context().Done():
            return
        }
    }
}

func sendMessageHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    userID := vars["userId"]
    
    log.Printf("Received send message request for user ID: %s", userID)
    
    clientsLock.RLock()
    waClient, exists := clients[userID]
    clientsLock.RUnlock()
    
    if !exists {
        log.Printf("Error: WhatsApp client not found for user ID: %s", userID)
        http.Error(w, "WhatsApp client not connected", http.StatusBadRequest)
        return
    }
    
    if !waClient.Client.IsConnected() {
        log.Printf("Error: WhatsApp client not connected for user ID: %s", userID)
        http.Error(w, "WhatsApp client not connected", http.StatusBadRequest)
        return
    }
    
    var req struct {
        Recipient string `json:"recipient"`
        Message   string `json:"message"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        log.Printf("Error decoding request body: %v", err)
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    
    // log.Printf("Sending message to: %s", req.Recipient)
    // log.Printf("Message content: %s", req.Message)
    // log.Printf("WhatsApp connection state: %v", waClient.Client.IsConnected())
    
    // Handle various formats of phone numbers and JIDs
    var recipient types.JID
    
    // Check if it's a phone number with + sign
    if strings.HasPrefix(req.Recipient, "+") {
        // Remove + and create JID
        phoneNumber := strings.TrimPrefix(req.Recipient, "+")
        recipient = types.NewJID(phoneNumber, "s.whatsapp.net")
        // log.Printf("Converted +number format to JID: %s", recipient.String())
    } else if strings.Contains(req.Recipient, "@") {
        // It's already in JID format, but we need to ensure it has no device part
        parts := strings.Split(req.Recipient, "@")
        if len(parts) != 2 {
            // log.Printf("Invalid JID format: %s", req.Recipient)
            http.Error(w, "Invalid recipient format", http.StatusBadRequest)
            return
        }
        
        // Create a clean JID with just the user part and server
        userPart := parts[0]
        serverPart := parts[1]
        
        // Remove any device part if present (numbers after colon)
        if strings.Contains(userPart, ":") {
            userPart = strings.Split(userPart, ":")[0]
        }
        
        recipient = types.NewJID(userPart, serverPart)
        // log.Printf("Cleaned JID format to: %s", recipient.String())
    } else {
        // Assume it's a plain phone number
        recipient = types.NewJID(req.Recipient, "s.whatsapp.net")
        // log.Printf("Using plain number as JID: %s", recipient.String())
    }
    
    msg := &waProto.Message{
        Conversation: proto.String(req.Message),
    }
    
    // Add a timeout context
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    _, err := waClient.Client.SendMessage(ctx, recipient, msg)
    if err != nil {
        // log.Printf("Error sending message: %v", err)
        http.Error(w, fmt.Sprintf("Failed to send message: %v", err), http.StatusInternalServerError)
        return
    }
    
    // log.Printf("Message sent successfully to: %s", recipient.String())
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"status": "sent"})
}



func statusHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    userID := vars["userId"]

    clientsLock.RLock()
    waClient, exists := clients[userID]
    clientsLock.RUnlock()

    status := "disconnected"
    jid := ""

    if exists && waClient.Client != nil && waClient.Client.IsConnected() {
        if waClient.Client.Store != nil && waClient.Client.Store.ID != nil {
            user := waClient.Client.Store.ID.User
            if user != "" {
                jid = user + "@s.whatsapp.net"
                waClient.JID = jid
                status = "connected"
            } else {
                // log.Printf("⚠️ Connected socket but JID not available for user %s", userID)
            }
        }
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "status":  status,
        "user_id": userID,
        "jid":     jid,
    })
}




func processMessages(messageQueue chan *MessageEvent) {
    for msg := range messageQueue {
        // log.Printf("📨 Message from %s: %s", msg.UserID, msg.Content)

        // Publish to broker
        messageBroker.Publish(msg)

        // 🔄 Forward to FastAPI
        go func(m *MessageEvent) {
            jsonData, _ := json.Marshal(map[string]string{
                "user_id": m.UserID,
                "content": m.Content,
            })

            resp, err := http.Post(
                "http://localhost:8000/internal/incoming-message",
                "application/json",
                strings.NewReader(string(jsonData)),
            )
            if err != nil {
                log.Printf("❌ Failed to forward message to FastAPI: %v", err)
                return
            }
            defer resp.Body.Close()
            log.Printf("✅ Forwarded message to FastAPI, status: %s", resp.Status)
        }(msg)
    }
}


// Add this new handler function
func pollMessagesHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    userID := vars["userId"]
    
    clientsLock.RLock()
    _, exists := clients[userID]
    clientsLock.RUnlock()
    
    if !exists {
        http.Error(w, "WhatsApp client not connected", http.StatusBadRequest)
        return
    }
    
    // Create a channel to receive messages from the broker
    ch := make(chan *MessageEvent, 10)
    
    // Subscribe to messages
    messageBroker.subscribersLock.Lock()
    if _, ok := messageBroker.subscribers[userID]; !ok {
        messageBroker.subscribers[userID] = []chan *MessageEvent{}
    }
    messageBroker.subscribers[userID] = append(messageBroker.subscribers[userID], ch)
    messageBroker.subscribersLock.Unlock()
    
    // Make sure we unsubscribe when done
    defer func() {
        messageBroker.subscribersLock.Lock()
        if subs, ok := messageBroker.subscribers[userID]; ok {
            for i, sub := range subs {
                if sub == ch {
                    messageBroker.subscribers[userID] = append(subs[:i], subs[i+1:]...)
                    close(ch)
                    break
                }
            }
        }
        messageBroker.subscribersLock.Unlock()
    }()
    
    // Wait for messages with a timeout
    select {
    case msg := <-ch:
        // We got a message, return it immediately
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode([]*MessageEvent{msg})
        
    case <-time.After(30 * time.Second):
        // No message received within timeout, return empty array
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode([]*MessageEvent{})
    }
}

func main() {

    ctx := context.Background()

    var err error
    storeContainer, err = sqlstore.New(
        ctx,
        "sqlite3",
        "file:whatsmeow.db?_foreign_keys=on",
        waLog.Stdout("database", "DEBUG", false),
    )
    if err != nil {
        log.Fatalf("Failed to connect to shared database: %v", err)
    }


    r := mux.NewRouter()
    
    // WhatsApp-related endpoints
    r.HandleFunc("/api/whatsapp/{userId}/qr", qrCodeHandler).Methods("GET")
    r.HandleFunc("/api/whatsapp/{userId}/status", statusHandler).Methods("GET")
    r.HandleFunc("/api/whatsapp/{userId}/send", sendMessageHandler).Methods("POST")
    r.HandleFunc("/api/whatsapp/{userId}/messages", messageStreamHandler)
    r.HandleFunc("/api/whatsapp/{userId}/disconnect", disconnectHandler).Methods("POST")

    
    // Add this new route
    r.HandleFunc("/api/whatsapp/{userId}/poll", pollMessagesHandler).Methods("GET")
    
    // Start the server
    srv := &http.Server{
        Addr:    ":8080",
        Handler: r,
    }
    
    // Run the server in a goroutine
    go func() {
        log.Printf("Starting WhatsApp service on :8080")
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("Server error: %v", err)
        }
    }()
    
    // Set up graceful shutdown
    stop := make(chan os.Signal, 1)
    signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
    <-stop
    
    log.Println("Shutting down server...")
    
    // Disconnect all WhatsApp clients
    clientsLock.Lock()
    for _, client := range clients {
        if client.Client.IsConnected() {
            client.Client.Disconnect()
        }
    }
    clientsLock.Unlock()
    
    // Shutdown the server
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    if err := srv.Shutdown(ctx); err != nil {
        log.Fatalf("Server shutdown error: %v", err)
    }
    
    log.Println("Server stopped")
}