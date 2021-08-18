package de.julius_hardt.crypto.shamirs_secret_sharing;

import com.nativeutils.NativeUtils;

import java.io.IOException;

/**
 * Implementation of Shamir's Secret Sharing powered by D. Sprenkels's sss library (https://github.com/dsprenkels/sss)
 */
public class ShamirsSecretSharing {
    static {
        try {
            NativeUtils.loadLibraryFromJar("/" + System.mapLibraryName("shamirssecretsharing"));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static ShamirsSecretSharing create() {
        return new ShamirsSecretSharing();
    }

    private ShamirsSecretSharing() {}

    /**
     * Implementation of the Share algorithm of Shamir's Secret Sharing powered by D. Sprenkels's sss library.
     *
     * Warning: This method IS NOT resistant against side channel attacks.
     *
     * @param shareCount the amount of shares to generate
     * @param threshold the minimum amount of shares that is required to reconstruct the secret
     * @param data the secret to share
     * @return an array of shares such that a subset of threshold distinct shares is necessary to reconstruct the secret
     */
    public native byte[][] share(int shareCount, int threshold, byte[] data);

    /**
     * Implementation of the Reconstruct algorithm of Shamir's Secret Sharing powered by D. Sprenkels's sss library.
     *
     * Warning: This method IS NOT resistant against side channel attacks.
     *
     * @param shares the shares to combine
     * @return the reconstructed secret
     */
    public native byte[] reconstruct(byte[][] shares) throws InvalidSharesException;
}
