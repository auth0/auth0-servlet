package com.auth0.lib;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Class to deliver the authentication result of the {@link RequestProcessor}
 */
public interface TokensCallback {

    /**
     * The Auth0 authentication succeeded. The User Id is available in the session by calling {@link ServletUtils#getSessionUserId(HttpServletRequest)}.
     *
     * @param req    the request.
     * @param res    the response.
     * @param tokens the tokens available after the authentication.
     */
    void onSuccess(HttpServletRequest req, HttpServletResponse res, Tokens tokens) throws IOException;

    /**
     * The Auth0 authentication failed.
     *
     * @param req the request.
     * @param res the response.
     * @param e   the cause of the failure.
     */
    void onFailure(HttpServletRequest req, HttpServletResponse res, Throwable e) throws IOException;
}
