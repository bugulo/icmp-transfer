# App
This app is able to encrypt file using AES and send it through ICMP echo request payload to specified server. The server then decrypts these packets and saves the respective file.

## Arguments
`-r <file>` - File to transfer\
`-s <host>` - Server hostname\
`-l` - Listener mode

## Build
`make clean` - Clean files generated during build process.\
`make secret` - Build project.\
`make` - Run secret target.

## Run
```
make
sudo ./secret -l
sudo ./secret -r some.file -s localhost
sudo ./secret -r some.file -s ::1
```

## Files
```
Makefile
README.md
secret.1
manual.pdf
main.cpp
```

## Improvements
- Transfer status in output
- Simultaneous active transfers on server