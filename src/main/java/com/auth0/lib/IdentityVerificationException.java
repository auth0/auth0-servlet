package com.auth0.lib;

public class IdentityVerificationException extends Exception {

    IdentityVerificationException(String message) {
        super(message);
    }

    IdentityVerificationException(String message, Throwable cause) {
        super(message, cause);
    }

}
