package com.auth0;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.ServletConfig;
import java.security.SecureRandom;

@SuppressWarnings("WeakerAccess")
public abstract class ServletUtils {

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
}
