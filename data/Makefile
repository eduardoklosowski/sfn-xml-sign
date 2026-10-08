.PHONY: all clean

all: ca.key ca.crt bcb.key bcb.crt client.key client.crt

clean:
	rm -f *.key *.crt *.csr

%.key:
	openssl genrsa -out $@ 2048

ca.crt: ca.key
	openssl req -x509 -new -key $< -out $@ -subj '/CN=Fake ICP-Brasil AC' -days 3653

%.csr: %.key
	openssl req -new -key $< -out $@ -subj '/CN=$*'

%.crt: %.csr ca.crt ca.key
	openssl x509 -req -CA ca.crt -CAkey ca.key -in $< -out $@ -copy_extensions copy -days 365
