package com.tempos21.t21crypt.exception;

public class CrypterException extends Exception {

    public CrypterException() {
        super();
    }

    public CrypterException(String detailMessage) {
        super(detailMessage);
    }

    public CrypterException(String detailMessage, Throwable throwable) {
        super(detailMessage, throwable);
    }

    public CrypterException(Throwable throwable) {
        super(throwable);
    }
}
