OPENSSL_PATH = ../..

build: errors.c  network.c  vasprintf.c network.h
	gcc -std=c11 -o np tryout.c errors.c  network.c  vasprintf.c -I ${OPENSSL_PATH}/openssl-1.1.1a/include/ -L ${OPENSSL_PATH}/openssl-1.1.1a  -lssl -lcrypto