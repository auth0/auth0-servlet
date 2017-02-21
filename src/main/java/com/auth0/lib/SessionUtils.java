package com.auth0.lib;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.util.io.pem.PemReader;

import javax.servlet.FilterConfig;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

@SuppressWarnings({"WeakerAccess", "unused"})
public abstract class SessionUtils {

    private static final String SESSION_STATE = "com.auth0.state";
    private static final String SESSION_NONCE = "com.auth0.nonce";
    private static final String SESSION_USER_ID = "com.auth0.userId";

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
     * Saves the given nonce in the request {@link HttpSession}.
     * If a nonce is already bound to the session, the value is replaced.
     *
     * @param req   the request.
     * @param nonce the nonce value to set.
     */
    public static void setSessionNonce(HttpServletRequest req, String nonce) {
        getSession(req).setAttribute(SESSION_NONCE, nonce);
    }

    /**
     * Removes the nonce present in the request {@link HttpSession} and then returns it.
     *
     * @param req the HTTP Servlet request.
     * @return the nonce value or null if it was not set.
     */
    static String removeSessionNonce(HttpServletRequest req) {
        String nonce = (String) getSession(req).getAttribute(SESSION_NONCE);
        getSession(req).removeAttribute(SESSION_NONCE);
        return nonce;
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
