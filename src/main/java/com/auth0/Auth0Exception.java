package com.auth0;

public class Auth0Exception extends RuntimeException {
    public Auth0Exception(String message, Throwable cause) {
        super(message, cause);
    }

    public Auth0Exception(String message) {
        super(message);
    }
}
