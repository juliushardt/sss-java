package de.julius_hardt.crypto.shamirs_secret_sharing;

public class InvalidSharesException extends Exception {
    public InvalidSharesException() {
    }

    public InvalidSharesException(String message) {
        super(message);
    }

    public InvalidSharesException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidSharesException(Throwable cause) {
        super(cause);
    }

    public InvalidSharesException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
