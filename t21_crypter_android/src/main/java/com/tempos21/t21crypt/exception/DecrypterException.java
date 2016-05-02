package com.tempos21.t21crypt.exception;

public class DecrypterException extends Exception {

    public DecrypterException() {
        super();
    }

    public DecrypterException(String detailMessage) {
        super(detailMessage);
    }

    public DecrypterException(String detailMessage, Throwable throwable) {
        super(detailMessage, throwable);
    }

    public DecrypterException(Throwable throwable) {
        super(throwable);
    }
}
