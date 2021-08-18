SUBDIRS = sss

# Detect operating system
ifeq ($(OS),Windows_NT)
	operating_system := Windows
else
	operating_system := $(shell uname -s)
endif

# OS specific targets
ifeq ($(operating_system),Windows)

all: shamirssecretsharing.dll

de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing.o: subdirs de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing.c
	gcc -g -c -I "${JAVA_HOME}\include" -I "${JAVA_HOME}\include\win32" de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing.c -o de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing.o

shamirssecretsharing.dll: de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing.o
	gcc -g -shared -o shamirssecretsharing.dll de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing.o sss/randombytes.o sss/sss.o sss/hazmat.o sss/tweetnacl.o -Wl,--add-stdcall-alias
	copy shamirssecretsharing.dll ..\src\main\resources\shamirssecretsharing.dll

else ifeq ($(operating_system),Darwin) # macOS

all: libshamirssecretsharing.dylib

de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing.o: subdirs de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing.c
	gcc -c -fPIC -I "${JAVA_HOME}/include" -I "${JAVA_HOME}/include/darwin" de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing.c -o de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing.o

libshamirssecretsharing.dylib: de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing.o
	gcc -dynamiclib -o libshamirssecretsharing.dylib de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing.o sss/randombytes.o sss/sss.o sss/hazmat.o sss/tweetnacl.o -lc
	cp libshamirssecretsharing.dylib ../src/main/resources/libshamirssecretsharing.dylib

else # Linux

all: libshamirssecretsharing.so

de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing.o: subdirs de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing.c
	gcc -c -fPIC -I "${JAVA_HOME}/include" -I "${JAVA_HOME}/include/linux" de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing.c -o de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing.o

libshamirssecretsharing.so: de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing.o
	gcc -shared -fPIC -o libshamirssecretsharing.so de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing.o sss/randombytes.o sss/sss.o sss/hazmat.o sss/tweetnacl.o -lc
	cp libshamirssecretsharing.so ../src/main/resources/libshamirssecretsharing.so

endif

# Common targets

.PHONY: subdirs $(SUBDIRS)

subdirs: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@
