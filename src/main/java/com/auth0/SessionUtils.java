package com.auth0;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Class that handles HTTP Session saving and retrieval.
 */
@SuppressWarnings("WeakerAccess")
public abstract class SessionUtils {

    private static final String STATE = "state";
    private static final String AUTH0_USER = "auth0UserId";

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
        getSession(req).setAttribute(STATE, state);
    }

    /**
     * Removes the state attribute from the session.
     *
     * @param req the HTTP Servlet request.
     */
    public static void removeState(HttpServletRequest req) {
        req.removeAttribute(STATE);
    }

    /**
     * Returns the object bound with the auth0 user id attribute in this session, or <code>null</code> if no object is bound to the auth0 user id.
     *
     * @param req the HTTP Servlet request.
     * @return the auth0 user id attribute value associated with the current session.
     */
    public static String getAuth0UserId(HttpServletRequest req) {
        return (String) getSession(req).getAttribute(AUTH0_USER);
    }

    /**
     * Binds the auth0 user id object to this session.
     * If an auth0 user id object is already bound to the session, the object is replaced.
     *
     * @param req    the HTTP Servlet request.
     * @param userId the auth0 user id attribute to bind to this session.
     */
    public static void setAuth0UserId(HttpServletRequest req, String userId) {
        getSession(req).setAttribute(AUTH0_USER, userId);
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
