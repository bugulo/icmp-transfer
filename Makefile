all: clean build

build:
	g++ main.cpp -lcrypto -lpcap -o secret

clean: 
	$(RM) secret