package main

import (
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "path/filepath"
    "strings"
)

const (
    pkeyDir = "./circuits/generated"
    vkeyDir = "./verifier/generated"
    port    = 8080
)

func main() {
    http.HandleFunc("/keys/", serveKey)

    fmt.Printf("Starting server on port %d...\n", port)
    err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
    if err != nil {
        fmt.Printf("Error starting server: %s\n", err)
    }
}

func serveKey(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    keyName := strings.TrimPrefix(r.URL.Path, "/keys/")

    if keyName == "" {
        // If no specific key is requested, list available keys
        pkeys, err := ioutil.ReadDir(pkeyDir)
        if err != nil {
            http.Error(w, fmt.Sprintf("Error reading directory: %v", err), http.StatusInternalServerError)
            return
        }
        vkeys, err := ioutil.ReadDir(vkeyDir)
        if err != nil {
            http.Error(w, fmt.Sprintf("Error reading directory: %v", err), http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "text/plain")
        for _, file := range pkeys {
            fmt.Fprintf(w, "%s\n", file.Name())
        }
        for _, file := range vkeys {
            fmt.Fprintf(w, "%s\n", file.Name())
        }
        return
    }

    var keyPath string
    if strings.HasPrefix(keyName, "pk") {
        keyPath = filepath.Join(pkeyDir, keyName)
    } else {
        keyPath = filepath.Join(vkeyDir, keyName)
    }

    fmt.Printf("Attempting to serve key: %s\n", keyPath)

    keyData, err := os.ReadFile(keyPath)
    if err != nil {
        if os.IsNotExist(err) {
            http.Error(w, "Key not found", http.StatusNotFound)
        } else {
            http.Error(w, fmt.Sprintf("Internal server error: %v", err), http.StatusInternalServerError)
        }
        return
    }

    w.Header().Set("Content-Type", "application/octet-stream")
    w.Write(keyData)
}
