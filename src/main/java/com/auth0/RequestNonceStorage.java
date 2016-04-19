package com.auth0;

import javax.servlet.http.HttpServletRequest;

public class RequestNonceStorage implements NonceStorage {

    private final HttpServletRequest request;

    public RequestNonceStorage(HttpServletRequest request) {
        this.request = request;
    }

    public String getState() {
        return (String) request.getSession(true).getAttribute("state");
    }

    public void setState(String nonce) {
        request.getSession(true).setAttribute("state", nonce);
    }
}
