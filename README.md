# sss-java
Java bindings for [Daan Sprenkels's Shamir secret sharing library](https://github.com/dsprenkels/sss)

## Features
* Simple, stateless API
* Self-contained: All native dependencies are included, so there is no need to deploy DLLs, dylibs or shared objects separately.
* Lightweight: Only one Maven dependency, no transitive dependencies.

## Limitations
* **These bindings have not been reviewed by experts**. This is an experimental project and should not be used in production without further review and risk assessment.
* Since this project uses sss under the hood, the maximum amount of shares is 255. Additionally, sss only supports non-proactive secret sharing. Be sure to read the documentation of sss to decide whether it fits your needs.
* Only works on Linux, macOS and Windows right now.
* While Daan Sprenkels's sss library is resistant against side-channel attacks, this library is **not**.
* Due to technical limitations of the Java runtime, this library needs to create a temporary file on application startup to load the native wrapper for sss. This may lead to a security vulnerability (see below).
* The native DLL for Windows and the dynamic library for macOS are currently not signed.

## Known issues
* **Possible elevation of privilege vulnerability:** This library uses `com.github.ramanrajarathinam:native-utils:1.0.0`  to load a JNI wrapper for sss. `native-utils` works by first extracting the DLL, dylib or shared object file to a temp directory and then using `System.load()` to load it. If an adversary manages to replace the temporary file on disk before `System.load` is called, they may be able to execute arbitrary code. To mitigate this vulnerability, make sure that your temp directory `System.getProperty("java.io.tmpdir")` has appropriate file-system permissions. To learn more about how the JNI wrapper is loaded, please refer to [NativeUtils.java](https://github.com/raman-rajarathinam/native-utils/blob/master/src/main/java/com/nativeutils/NativeUtils.java) of `native-utils`.

## Installation
to be updated once the artifacts are published to a Maven repository

## Usage
### Initialization
```java
// Create an instance of Shamir's Secret Sharing scheme.
// This object is stateless and can be reused for subsequent sharing and reconstruction operations.
ShamirsSecretSharing secretSharing = ShamirsSecretSharing.create();
```

### Sharing a secret
```java
// The secret to share must be a byte array. If you want to share e.g. a string, you need to convert it to a byte array first.
byte[] secret = new byte[] { 0xaa, 0xbb, 0xcc, 0xdd };

// Number of shares to generate. Must be in the range 0 < n < 256
int n = 19;

// Minimum number of shares required to reconstruct the secret. Must be in the range 0 < t <= n
int t = 10;

// Create the shares, which results in an array of length n.
// Each element of this array is a byte array that represents a single share.
byte[][] shares = secretSharing.share(n, t, secret);


// Send the shares to shareholders
for (int i = 0; i < shares.length; i++) {
    YourCode.sendShareToShareholder(i, shares[i]);
}

// This library never modifies input parameters.
// You are responsible for clearing the secret from memory once you no longer need it!
// Beware of possible compiler and runtime optimizations that may prevent the following lines from taking effect.
Arrays.fill(secret, (byte)0);
for (byte[] share : shares) {
    Arrays.fill(share, (byte)0);
}
```

### Reconstructing a secret
```java
// To reconstruct the secret, at least t shares are needed.
// The order of the shares in the array does not matter.
// Each element of the array should contain an actual share. Null values are not allowed.
byte[][] shares = YourCode.fetchSharesFromShareholders();

byte[] secret = null;
try {
    // Reconstruct the secret
    secret = secretSharing.reconstruct(shares);
    YourCode.doSomethingWith(secret);
}
catch (InvalidSharesException exc) {
    // If the reconstruction fails, an InvalidSharesException is thrown.
    System.out.println("Reconstructing the secret failed: " + exc.getMessage());
}
finally {
    // Clear the secret from memory
    if (secret != null) {
        Arrays.fill(secret, (byte)0);
    }
    for (byte[] share : shares) {
        Arrays.fill(share, (byte)0);
    }
}
```

## Setting Up Your Development Environment
1. Download and install gcc and [GNU Make](https://www.gnu.org/software/make/) (the make command).

    Ubuntu:
    ```sh
    sudo apt update && sudo apt install build-essential
    ```

    macOS:
    ```sh
    xcode-select --install
    ```
    On Windows, you can use [MinGW](http://mingw.org/) and GNU Make for Win32. If you use [Chocolatey](https://chocolatey.org/), you can install it using these commands:
    ```powershell
    # Run as Administrator:
    choco install mingw
    choco install make
    ```
1. Clone the project from GitHub with submodules:
    ```sh
    git clone --recurse-submodules https://github.com/juliushardt/sss-java.git
    ```
1. Fix symlinks: If you use Windows and git is not configured to create symlinks correctly, you need to fix the broken symlinks in the sss submodule:
    1. By default, creating symbolic links requires administrative privileges. [You can opt out of this by enabling developer mode on your machine](https://blogs.windows.com/windowsdeveloper/2016/12/02/symlinks-windows-10/). To do so, type Win+R, open `ms-settings:developers` and switch on "Developer Mode".
    1. Open a PowerShell console and create the symbolic links:
    ```powershell
    cd \path\to\sss-java\
    cd .\native\sss\
    Remove-Item -Path randombytes.h
    Remove-Item -Path randombytes.c
    New-Item -ItemType SymbolicLink -Path randombytes.h -Target .\randombytes\randombytes.h
    New-Item -ItemType SymbolicLink -Path randombytes.c -Target .\randombytes\randombytes.c
    ```
1. Export an environment variable named `CC` which contains the path to your gcc binary:
    ```sh
    # Bash
    export CC="gcc"
    ```
    ```powershell
    # Powershell
    $env:CC="gcc"
    ```
1. Make sure that the environment variable `JAVA_HOME` is set and points to the JDK you want to use:
    ```sh
    # Bash
    # Check if JAVA_HOME is set:
    echo $JAVA_HOME
    # If JAVA_HOME is not set, update it. For example:
    export JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home
    ```
    ```powershell
    # Powershell
    # Check if JAVA_HOME is set:
    $env:JAVA_HOME
    # If JAVA_HOME is not set, update it. For example:
    $env:JAVA_HOME = "C:\Program Files\AdoptOpenJDK\jdk-8.0.222.10-hotspot\"
    ```

## Building
```sh
cd /path/to/sss-java
# Build the native wrapper library for your platform
make

# Build the Java library
./gradlew build
```
On Windows, you may get an error like this while running `make`:
```
process_begin: CreateProcess(NULL, uname -s, ...) failed.
Makefile:7: pipe: No error
```
This is because the makefile of sss tries to execute the command `uname -s`, which does not exist on Windows. However, the build works anyway, so you can simply ignore the error. In the future, we should contribute proper Windows support back to sss and randombytes.
<!-- Windows: MinGW, CC env variable, fix symlinks, Developer mode for symlinks without admin, clone with submodules, JAVA_HOME -->