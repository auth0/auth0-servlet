package com.auth0;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Class that handles HTTP Session saving and retrieval.
 */
@SuppressWarnings("WeakerAccess")
public abstract class SessionUtils {

    private static final String STATE = "state";
    private static final String TOKENS = "tokens";
    private static final String AUTH0_USER = "auth0User";

    /**
     * Returns the object bound with the state attribute in this session, or <code>null</code> if no object is bound to state.
     *
     * @param req the HTTP Servlet request
     * @return the state attribute value associated with the current session
     */
    public static String getState(HttpServletRequest req) {
        return (String) getSession(req).getAttribute(STATE);
    }

    /**
     * Binds the state object to this session.
     * If a state object is already bound to the session, the object is replaced.
     *
     * @param req   the HTTP Servlet request.
     * @param state the state attribute to bind to this session.
     */
    public static void setState(HttpServletRequest req, String state) {
        if (state == null) {
            getSession(req).removeAttribute(STATE);
        } else {
            getSession(req).setAttribute(STATE, state);
        }
    }

    /**
     * Returns the object bound with the tokens attribute in this session, or <code>null</code> if no object is bound to tokens.
     *
     * @param req the HTTP Servlet request.
     * @return the tokens attribute value associated with the current session.
     */
    public static Tokens getTokens(HttpServletRequest req) {
        return (Tokens) getSession(req).getAttribute(TOKENS);
    }

    /**
     * Binds the tokens object to this session.
     * If a tokens object is already bound to the session, the object is replaced.
     *
     * @param req    the HTTP Servlet request.
     * @param tokens the tokens attribute to bind to this session.
     */
    public static void setTokens(HttpServletRequest req, Tokens tokens) {
        getSession(req).setAttribute(TOKENS, tokens);
    }

    /**
     * Returns the object bound with the auth0 user attribute in this session, or <code>null</code> if no object is bound to the auth0 user.
     *
     * @param req the HTTP Servlet request.
     * @return the auth0 user attribute value associated with the current session.
     */
    public static Auth0User getAuth0User(HttpServletRequest req) {
        return (Auth0User) getSession(req).getAttribute(AUTH0_USER);
    }

    /**
     * Binds the auth0 user object to this session.
     * If an auth0 user object is already bound to the session, the object is replaced.
     *
     * @param req       the HTTP Servlet request.
     * @param auth0User the auth0 user attribute to bind to this session.
     */
    public static void setAuth0User(HttpServletRequest req, Auth0User auth0User) {
        getSession(req).setAttribute(AUTH0_USER, auth0User);
    }

    /**
     * Get current session or create one if it does not already exist.
     *
     * @param req the HTTP Servlet request.
     * @return the HTTP Session.
     */
    private static HttpSession getSession(HttpServletRequest req) {
        return req.getSession(true);
    }

}
