package com.auth0.lib;

public class InvalidRequestException extends IdentityVerificationException {
    private final String description;

    InvalidRequestException(String error) {
        this(error, null);
    }

    InvalidRequestException(String error, String description) {
        super("The request contains an error: " + error);
        this.description = description;
    }

    /**
     * Getter for the description of the error.
     *
     * @return the error description if available, null otherwise.
     */
    @SuppressWarnings("unused")
    public String getErrorDescription() {
        return description;
    }
}
