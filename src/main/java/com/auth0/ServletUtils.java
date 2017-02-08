package com.auth0;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.FilterConfig;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.SecureRandom;

@SuppressWarnings("WeakerAccess")
public abstract class ServletUtils {

    private static final String SESSION_STATE = "com.auth0.state";
    private static final String SESSION_USER_ID = "com.auth0.userId";

    /**
     * Attempts to get a required property from the {@link ServletConfig}. If it's not present there, it will try
     * to search it in the {@link javax.servlet.ServletContext}.
     *
     * @param parameter the parameter name to lookup
     * @param config    the servlet config to search
     * @return the parameter value
     * @throws IllegalArgumentException if the required value is not present or it's empty.
     */
    static String readRequiredParameter(String parameter, ServletConfig config) throws IllegalArgumentException {
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

    /**
     * Attempts to get a required property from the {@link ServletConfig}.
     *
     * @param parameter the parameter name to lookup
     * @param config    the servlet config to search
     * @return the parameter value
     * @throws IllegalArgumentException if the required value is not present or it's empty.
     */
    static String readLocalRequiredParameter(String parameter, ServletConfig config) throws IllegalArgumentException {
        String initParam = config.getInitParameter(parameter);
        if (StringUtils.isNotEmpty(initParam)) {
            return initParam;
        }
        throw new IllegalArgumentException(parameter + " needs to be defined");
    }

    /**
     * Attempts to get a required property from the {@link FilterConfig}.
     *
     * @param parameter the parameter name to lookup
     * @param config    the servlet config to search
     * @return the parameter value
     * @throws IllegalArgumentException if the required value is not present or it's empty.
     */
    static String readLocalRequiredParameter(String parameter, FilterConfig config) throws IllegalArgumentException {
        String initParam = config.getInitParameter(parameter);
        if (StringUtils.isNotEmpty(initParam)) {
            return initParam;
        }
        throw new IllegalArgumentException(parameter + " needs to be defined");
    }

    /**
     * Attempts to get a boolean property from the {@link ServletConfig}. The value must be 'true' for the flag to be true.
     *
     * @param name   the flag name to lookup
     * @param config the servlet config to search
     * @return whether the value was present and it's value was equal to 'true' or not.
     */
    static boolean isFlagEnabled(String name, ServletConfig config) {
        String textFlag = config.getInitParameter(name);
        return textFlag != null && textFlag.equals("true");
    }

    /**
     * Generates a new random string using {@link SecureRandom}.
     * The output can be used as State or Nonce values for API requests.
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
     * Check's if the request {@link HttpSession} saved state is equal to the given state.
     * After the check, the value will be removed from the session.
     *
     * @param req   the request
     * @param state the state value to compare against.
     * @return whether the state matches the expected one or not.
     */
    public static boolean checkSessionState(HttpServletRequest req, String state) {
        String currentState = (String) getSession(req).getAttribute(SESSION_STATE);
        getSession(req).removeAttribute(SESSION_STATE);
        return (currentState == null && state == null) || currentState != null && currentState.equals(state);
    }

    /**
     * Saves the given state in the request {@link HttpSession}.
     * If a state is already bound to the session, the value is replaced.
     *
     * @param req   the request.
     * @param state the state value to set.
     */
    public static void setSessionState(HttpServletRequest req, String state) {
        getSession(req).setAttribute(SESSION_STATE, state);
    }

    /**
     * Returns the user id present in the request {@link HttpSession}, or null if it's not set.
     *
     * @param req the HTTP Servlet request.
     * @return the user id value.
     */
    public static String getSessionUserId(HttpServletRequest req) {
        return (String) getSession(req).getAttribute(SESSION_USER_ID);
    }

    /**
     * Saves the given user id in the request {@link HttpSession}.
     * If a user id is already bound to the session, the value is replaced.
     *
     * @param req    the request.
     * @param userId the user id value to set.
     */
    static void setSessionUserId(HttpServletRequest req, String userId) {
        getSession(req).setAttribute(SESSION_USER_ID, userId);
    }

    private static HttpSession getSession(HttpServletRequest req) {
        return req.getSession(true);
    }
}
