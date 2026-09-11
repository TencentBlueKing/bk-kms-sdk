# Assumes headers under /usr/local/include/bk-kms and libbkkms.a under
# /usr/local/lib. Adapt to your own build system as needed.
#
# Links libbkkms / OpenSSL statically and the system libraries (pthread,
# dl) dynamically to avoid pulling glibc's NSS / DNS resolution fully
# static.

.PHONY: decrypt clean

decrypt:
	g++ -std=c++11 -O2 -o decrypt main.cpp -I/usr/local/include -L/usr/local/lib -L/usr/local/lib64 -Wl,-Bstatic -lbkkms -lssl -lcrypto -Wl,-Bdynamic -lpthread -ldl

clean:
	@rm -f decrypt
