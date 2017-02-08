package com.auth0;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.SecureRandom;

@SuppressWarnings("WeakerAccess")
public abstract class ServletUtils {

    private static final String SESSION_STATE = "com.auth0.state";
    private static final String SESSION_USER_ID = "com.auth0.userId";

    /**
     * Attempts to get a property from the servlet context
     *
     * @param parameter the parameter name to lookup
     * @param config    the servlet config to search
     * @return the parameter value
     */
    static String readRequiredParameter(String parameter, ServletConfig config) {
        String initParam = config.getInitParameter(parameter);
        if (StringUtils.isNotEmpty(initParam)) {
            return initParam;
        }
        String servletContextInitParam = config.getServletContext().getInitParameter(parameter);
        if (StringUtils.isNotEmpty(servletContextInitParam)) {
            return servletContextInitParam;
        }
        throw new IllegalArgumentException(parameter + " needs to be defined");
    }

    static boolean isFlagEnabled(String key, ServletConfig config) {
        String textFlag = config.getInitParameter(key);
        return textFlag != null && textFlag.equals("true");
    }

    /**
     * Generates a new random string using {@link SecureRandom}.
     * The output can be used as state or nonce for API requests.
     *
     * @return a new random string.
     */
    public static String secureRandomString() {
        final SecureRandom sr = new SecureRandom();
        final byte[] randomBytes = new byte[32];
        sr.nextBytes(randomBytes);
        return Base64.encodeBase64URLSafeString(randomBytes);
    }


    /**
     * Returns the object bound with the state attribute in this session, or <code>null</code> if no object is bound to state.
     *
     * @param req the HTTP Servlet request
     * @return the state attribute value associated with the current session
     */
    public static boolean checkSessionState(HttpServletRequest req, String state) {
        String currentState = (String) getSession(req).getAttribute(SESSION_STATE);
        getSession(req).removeAttribute(SESSION_STATE);
        return (currentState == null && state == null) || currentState != null && currentState.equals(state);
    }


    /**
     * Binds the state object to this session.
     * If a state object is already bound to the session, the object is replaced.
     *
     * @param req   the HTTP Servlet request.
     * @param state the state attribute to bind to this session.
     */
    public static void setSessionState(HttpServletRequest req, String state) {
        getSession(req).setAttribute(SESSION_STATE, state);
    }

    /**
     * Returns the object bound with the auth0 user id attribute in this session, or <code>null</code> if no object is bound to the auth0 user id.
     *
     * @param req the HTTP Servlet request.
     * @return the auth0 user id attribute value associated with the current session.
     */
    public static String getSessionUserId(HttpServletRequest req) {
        return (String) getSession(req).getAttribute(SESSION_USER_ID);
    }

    /**
     * Binds the auth0 user id object to this session.
     * If an auth0 user id object is already bound to the session, the object is replaced.
     *
     * @param req    the HTTP Servlet request.
     * @param userId the auth0 user id attribute to bind to this session.
     */
    static void setSessionUserId(HttpServletRequest req, String userId) {
        getSession(req).setAttribute(SESSION_USER_ID, userId);
    }

    private static HttpSession getSession(HttpServletRequest req) {
        return req.getSession(true);
    }
}
