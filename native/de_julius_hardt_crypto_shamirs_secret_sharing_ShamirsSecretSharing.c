#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing.h"
#include "sss/sss.h"

#define ILLEGAL_ARGUMENT_EXCEPTION_CLASSNAME "java/lang/IllegalArgumentException"
#define BAD_PADDING_EXCEPTION_CLASSNAME "javax/crypto/BadPaddingException"
#define ELSA_INVALID_SHARES_EXCEPTION_CLASSNAME "de/julius_hardt/crypto/shamirs_secret_sharing/InvalidSharesException"

#define xstr(a) str(a)
#define str(a) #a

/*
 * Class:     de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing
 * Method:    share
 * Signature: (II[B)[[B
 *
 * Implementation of Shamir's Secret Sharing: Share(n, t, data).
 * Takes a secret and creates n shares. t shares are needed to reconstruct the secret.
 * 
 * Parameters:
 * env: JNI environment
 * thisObject: the object on which the function is called
 * shareCount: n (0 < n)
 * threshold: t (0 < t <= n)
 * dataArray: The secret to share
 * 
 * Returns an array of shares that can be transmitted to the respective shareholders.
 * 
 * Warning: This function IS NOT resistant against side channel attacks.
 */
JNIEXPORT jobjectArray JNICALL Java_de_julius_1hardt_crypto_shamirs_1secret_1sharing_ShamirsSecretSharing_share
  (JNIEnv * env, jobject thisObject, jint shareCount, jint threshold, jbyteArray dataArray) {
      if (dataArray == NULL) {
        return NULL;
    }

    jsize inputDataLength = (*env)->GetArrayLength(env, dataArray);

    // If the length of input data is not a whole multiple of sss_MLEN, we need ceil(inputDataLength / sss_MLEN) blocks.
    // Otherwise, we need (inputDataLength / sss_MLEN) + 1 blocks due to padding.
    // Thus, in either case, floor(inputDataLength / sss_MLEN) + 1 blocks are required.
    int neededBlocks = (inputDataLength / sss_MLEN) + 1; // Fast version of floor(inputDataLength / sss_MLEN) + 1
    // printf("Needed blocks: %d\n", neededBlocks);

    // Create resulting (outer) array that contains the generated shares
    jclass byteArrayClass = (*env)->FindClass(env, "[B"); // "[B" represents the byte[] class
    jobjectArray outerJavaArray = (*env)->NewObjectArray(env, shareCount, byteArrayClass, NULL);
    
    // Create inner arrays for the shares
    jbyteArray innerJavaArrays[shareCount];
    for (int i = 0; i < shareCount; i++) {
        jbyteArray innerArray = (*env)->NewByteArray(env, neededBlocks * sss_SHARE_LEN);
        innerJavaArrays[i] = innerArray;
        (*env)->SetObjectArrayElement(env, outerJavaArray, i, innerArray);
    }

    // Pin and get input buffer (or a copy if the JVM does not suppport pinning)
    jbyte* data = (*env)->GetPrimitiveArrayCritical(env, dataArray, NULL);

    // Pin and get buffers for the individual shares, i.e. the buffers of the inner arrays of the result
    jbyte* shares[shareCount];
    for (int i = 0; i < shareCount; i++) {
        shares[i] = (*env)->GetPrimitiveArrayCritical(env, innerJavaArrays[i], NULL);
    }

    // Process every but the last block
    for (int i = 0; i < neededBlocks - 1; i++) {
        // Perform secret sharing
        sss_Share block[shareCount];
        sss_create_shares(block, &data[i * sss_MLEN], shareCount, threshold);

        // Copy data to Java heap
        for (int j = 0; j < shareCount; j++) {
            memcpy(&shares[j][i * sss_SHARE_LEN], &block[j], sss_SHARE_LEN);
        }
    }

    // Last block: Perform PKCS#7 padding
    size_t actual_size = inputDataLength % sss_MLEN;
    // printf("Actual last block size: %d\n", actual_size);
    // Pad input and perform secret sharing on the padded input
    uint8_t paddedData[sss_MLEN];
    memcpy(paddedData, &data[(neededBlocks - 1) * sss_MLEN], actual_size);
    uint8_t paddingByte = sss_MLEN - actual_size;
    memset(&paddedData[actual_size], paddingByte, sss_MLEN - actual_size);

    // Perform secret sharing
    sss_Share block[shareCount];
    sss_create_shares(block, paddedData, shareCount, threshold);

    // Copy data to Java heap
    for (int j = 0; j < shareCount; j++) {
        memcpy(&shares[j][(neededBlocks - 1) * sss_SHARE_LEN], &block[j], sss_SHARE_LEN);
    }

    // Release shares (in reverse order)
    for (int i = shareCount - 1; i >= 0; i--) {
        (*env)->ReleasePrimitiveArrayCritical(env, innerJavaArrays[i], shares[i], 0);
    }

    // Release data
    // JNI_ABORT: Do not update the data on the Java heap. Free the space used by the copy.
    // Since we don't modify the input array, it does not need to be updated.
    (*env)->ReleasePrimitiveArrayCritical(env, dataArray, data, JNI_ABORT);

    return outerJavaArray;
}

/*
 * Class:     de_julius_hardt_crypto_shamirs_secret_sharing_ShamirsSecretSharing
 * Method:    reconstruct
 * Signature: ([[B)[B
 *
 * Implementation of Shamir's Secret Sharing: Reconstruct(shares).
 * 
 * Parameters:
 * env: JNI environment
 * thisObject: the object on which the function is called
 * shareArray: the shares to combine
 * 
 * Returns the reconstructed secret.
 * 
 * Warning: This function IS NOT resistant against side channel attacks.
 */
JNIEXPORT jbyteArray JNICALL Java_de_julius_1hardt_crypto_shamirs_1secret_1sharing_ShamirsSecretSharing_reconstruct
  (JNIEnv * env, jobject thisObject, jobjectArray shareArray) {
    // Handle null and empty array inputs and get the size of the outer array
    if (shareArray == 0) {
        return NULL;
    }
    jsize shareCount = (*env)->GetArrayLength(env, shareArray);
    if (shareCount == 0) {
        return (*env)->NewByteArray(env, 0);
    }

    // Get the elements of the outer array
    jbyteArray javaShares[shareCount];
    for (int i = 0; i < shareCount; i++) {
        jbyteArray arr = (*env)->GetObjectArrayElement(env, shareArray, i);
        if (arr == NULL) {
            jclass exceptionClass = (*env)->FindClass(env, ILLEGAL_ARGUMENT_EXCEPTION_CLASSNAME);
            (*env)->ThrowNew(env, exceptionClass, "None of the inner arrays (shares) can be null.");
            return NULL;
        }
        javaShares[i] = arr;
    }

    // Get share size, i.e. the length of the inner arrays adn verify all of the inner arrays are of the same size
    jsize totalShareSize = (*env)->GetArrayLength(env, javaShares[0]);
    if (totalShareSize % sss_SHARE_LEN != 0) {
        jclass exceptionClass = (*env)->FindClass(env, ILLEGAL_ARGUMENT_EXCEPTION_CLASSNAME);
        (*env)->ThrowNew(env, exceptionClass, "The lengths of all inner arrays (shares) must be a whole multiple of " xstr(sss_SHARE_LEN) ".");
        return NULL;
    }

    for (int i = 1; i < shareCount; i++) {
        jsize shareSize = (*env)->GetArrayLength(env, javaShares[i]);
        if (shareSize != totalShareSize) {
            jclass exceptionClass = (*env)->FindClass(env, ILLEGAL_ARGUMENT_EXCEPTION_CLASSNAME);
            (*env)->ThrowNew(env, exceptionClass, "All inner arrays (shares) must be of the same size.");
            return NULL;
        }
    }

    int blockCount = totalShareSize / sss_SHARE_LEN;
    // printf("Block count: %d\n", blockCount);
    // printf("Data length: %d\n", dataLength);

    sss_Share block[shareCount];
    // Process last block first to get the padding which is needed to determine the size of the output data.
    // Copy data from Java heap
    for (int j = 0; j < shareCount; j++) {
        (*env)->GetByteArrayRegion(env, javaShares[j], totalShareSize - sss_SHARE_LEN, sss_SHARE_LEN, block[j]);
    }

    // Combine shares
    uint8_t lastBlock[sss_MLEN];
    int sss_result;
    sss_result = sss_combine_shares(lastBlock, block, shareCount);
    // printf("Block %d - sss_combine_shares result: %d\n", blockCount - 1, sss_result);
    if (sss_result != 0) {
        jclass exceptionClass = (*env)->FindClass(env, ELSA_INVALID_SHARES_EXCEPTION_CLASSNAME);
        (*env)->ThrowNew(env, exceptionClass, "The reconstruction of the secret failed.");
        return NULL;
    }

    // Determine padding
    uint8_t padding = lastBlock[sss_MLEN - 1];
    // printf("Padding: %d\n", padding);

    // Verify padding I: Padding must be smaller than or equal to sss_MLEN
    if (padding > sss_MLEN) {
        // Invalid padding
        jclass exceptionClass = (*env)->FindClass(env, BAD_PADDING_EXCEPTION_CLASSNAME);
        (*env)->ThrowNew(env, exceptionClass, "The padding bytes must be smaller than or equal to " xstr(sss_MLEN) ".");
        return NULL;
    }

    // Verify padding II: The last [padding] bytes must be equal to [padding]
    for (int i = sss_MLEN - padding; i < sss_MLEN - 1; i++) {
        if (lastBlock[i] != padding) {
            // Invalid padding
            jclass exceptionClass = (*env)->FindClass(env, BAD_PADDING_EXCEPTION_CLASSNAME);
            (*env)->ThrowNew(env, exceptionClass, "Invalid padding");
            return NULL;
        }
    }

    jbyteArray result = (*env)->NewByteArray(env, blockCount * sss_MLEN - padding);
    jbyte* data = (*env)->GetPrimitiveArrayCritical(env, result, NULL);

    // Copy combined last block into the output buffer
    memcpy(&data[(blockCount - 1) * sss_MLEN], lastBlock, sss_MLEN - padding);

    jbyte* shares[shareCount];
    for (int i = 0; i < shareCount; i++) {
        shares[i] = (*env)->GetPrimitiveArrayCritical(env, javaShares[i], NULL);
    }

    // Process the remaining blocks
    for (int i = 0; i < blockCount - 1; i++) {
        // Copy data from Java heap
        for (int j = 0; j < shareCount; j++) {
            memcpy(&block[j], &shares[j][i * sss_SHARE_LEN], sss_SHARE_LEN);
            // (*env)->GetByteArrayRegion(env, javaShares[j], i * sss_SHARE_LEN, sss_SHARE_LEN, (jbyte*)&block[j]);
        }

        // Combine shares
        sss_result = sss_combine_shares(&data[i * sss_MLEN], block, shareCount);
        // printf("Block %d - sss_combine_shares result: %d\n", i, sss_result);
        if (sss_result != 0) {
            // Release data first!
            for (int j = shareCount - 1; j >= 0; j--) {
                (*env)->ReleasePrimitiveArrayCritical(env, javaShares[j], shares[j], JNI_ABORT);
            }
            (*env)->ReleasePrimitiveArrayCritical(env, result, data, 0);

            jclass exceptionClass = (*env)->FindClass(env, ELSA_INVALID_SHARES_EXCEPTION_CLASSNAME);
            (*env)->ThrowNew(env, exceptionClass, "The reconstruction of the secret failed.");
            return NULL;
        }
    }

    // Release data
    for (int j = shareCount - 1; j >= 0; j--) {
        (*env)->ReleasePrimitiveArrayCritical(env, javaShares[j], shares[j], JNI_ABORT);
    }
    (*env)->ReleasePrimitiveArrayCritical(env, result, data, 0);

    return result;
}