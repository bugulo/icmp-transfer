.PHONY: all clean

all: secret

secret:
	$(CXX) main.cpp -lcrypto -lpcap -pedantic -Wall -Wextra -o $@

clean: 
	$(RM) secret