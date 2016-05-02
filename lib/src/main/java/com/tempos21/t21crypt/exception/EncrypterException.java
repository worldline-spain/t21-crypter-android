package com.tempos21.t21crypt.exception;

public class EncrypterException extends Exception {

    public EncrypterException() {
        super();
    }

    public EncrypterException(String detailMessage) {
        super(detailMessage);
    }

    public EncrypterException(String detailMessage, Throwable throwable) {
        super(detailMessage, throwable);
    }

    public EncrypterException(Throwable throwable) {
        super(throwable);
    }
}
