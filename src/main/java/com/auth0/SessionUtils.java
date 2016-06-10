package com.auth0;

import com.auth0.authentication.result.Credentials;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Holds conveniences for getting / setting key session attributes
 * used as part of the library
 */
public class SessionUtils {

    public static final String STATE = "state";
    public static final String TOKENS = "tokens";
    public static final String AUTH0_USER = "auth0User";

    protected static HttpSession getSession(final HttpServletRequest req) {
        return req.getSession(true);
    }

    public static String getState(final HttpServletRequest req) {
        return (String) getSession(req).getAttribute(STATE);
    }

    public static void setState(final HttpServletRequest req, final String state) {
        getSession(req).setAttribute(STATE, state);
    }

    public static Credentials getTokens(final HttpServletRequest req) {
        return (Credentials) getSession(req).getAttribute(TOKENS);
    }

    public static void setTokens(final HttpServletRequest req, final Credentials tokens) {
        getSession(req).setAttribute(TOKENS, tokens);
    }

    public static Auth0User getAuth0User(final HttpServletRequest req) {
        return (Auth0User) getSession(req).getAttribute(AUTH0_USER);
    }

    public static void setAuth0User(final HttpServletRequest req, final Auth0User auth0User) {
        getSession(req).setAttribute(AUTH0_USER, auth0User);
    }

}
