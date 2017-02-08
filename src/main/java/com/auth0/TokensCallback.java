package com.auth0;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

interface TokensCallback {

    /**
     * Actions / navigation to take when a request is deemed successful by this callback handler
     */
    void onSuccess(HttpServletRequest req, HttpServletResponse res, Tokens tokens) throws IOException;

    /**
     * Actions / navigation to take when a request is deemed unsuccessful by this callback handler
     */
    void onFailure(HttpServletRequest req, HttpServletResponse res, Throwable e) throws IOException;
}
