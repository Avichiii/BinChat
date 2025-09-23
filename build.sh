#!/bin/bash
echo "building server..."
gcc -w -o build/server src/globals.c src/server.c src/crypto.c src/utils.c -I include -lcrypto -lssl -pthread

echo "building client..."
if [[ $? -eq 0 ]] then
    gcc -w -o build/client src/globals.c src/client.c src/crypto.c src/utils.c -I include -lcrypto -lssl -pthread
fi