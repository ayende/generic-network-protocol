OPENSSL_PATH = ../..

build:  tryout.c errors.c platform.c protocol.c network.c vasprintf.c utils.c
	gcc -std=gnu11 -o np tryout.c errors.c platform.c protocol.c network.c utils.c vasprintf.c -I ${OPENSSL_PATH}/openssl-1.1.1a/include/ -L ${OPENSSL_PATH}/openssl-1.1.1a  -lssl -lcrypto