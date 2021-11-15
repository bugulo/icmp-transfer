.PHONY: all clean

all: secret

secret:
	$(CXX) main.cpp -lcrypto -lssl -lpcap -pedantic -Wall -Wextra -o $@

clean: 
	$(RM) secret