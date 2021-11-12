.PHONY: all clean

all: secret

secret:
	$(CXX) main.cpp -lcrypto -lpcap -o $@

clean: 
	$(RM) secret