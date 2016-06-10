package com.auth0;

import org.apache.commons.lang3.Validate;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Convenience Utils methods for manipulating the nonce key/value pair held in state param
 * Used for CSRF protection - should always be sent with login request
 *
 * We assign on login, and remove on successful callback completion
 * callback request is checked for validity by correctly matching state in http request
 * with state held in storage (library uses http session)
 *
 * By using a nonce attribute in the state request param, we can also add additional attributes
 * as needed such as externalRedirectURL for SSO scenarios etc
 *
 * Examples of query param:
 *
 *  queryString = "nonce=B4AD596E418F7CE02A703B42F60BAD8F";
 *  queryString = "externalRedirectUrl=http://localhost:3099/callback";
 *  queryString = "nonce=B4AD596E418F7CE02A703B42F60BAD8F&externalRedirectUrl=http://localhost:3099/callback";
 *
 */
public class NonceUtils {

    public static final String NONCE_KEY = "nonce";


    public static void addNonceToStorage(final HttpServletRequest req) {
        final String stateFromStorage = SessionUtils.getState(req) != null ? SessionUtils.getState(req) : "";
        // only add if no existing entry..
        if (!hasNonce(stateFromStorage)) {
            final String updatedState = replaceEntryInQueryParams(stateFromStorage, NONCE_KEY, NonceFactory.create());
            SessionUtils.setState(req, updatedState);
        }
    }

    public static void removeNonceFromStorage(final HttpServletRequest req) {
        final String stateFromStorage = SessionUtils.getState(req) != null ? SessionUtils.getState(req) : "";
        final String stateFromStorageWithoutNonce = removeFromQueryParams(stateFromStorage, NONCE_KEY);
        SessionUtils.setState(req, stateFromStorageWithoutNonce);
    }

    public static boolean matchesNonceInStorage(final HttpServletRequest req, final String stateFromRequest) {
        final String nonceFromRequest = parseFromQueryParams(stateFromRequest, NONCE_KEY);
        final String stateFromStorage = SessionUtils.getState(req);
        final String nonceFromStorage = parseFromQueryParams(stateFromStorage, NONCE_KEY);
        return nonceFromRequest != null && !nonceFromRequest.isEmpty() && nonceFromRequest.equals(nonceFromStorage);
    }

    protected static boolean hasNonce(final String state) {
        return parseFromQueryParams(state, NONCE_KEY) != null;
    }

    protected static String replaceEntryInQueryParams(final String queryParams, final String key, final String value) {
        Validate.notNull(queryParams);
        Validate.notNull(key);
        Validate.notNull(value);
        final StringBuilder builder = new StringBuilder();
        final String updatedQueryParams = removeFromQueryParams(queryParams, key);
        if (updatedQueryParams.isEmpty()) {
            builder.append(key).append("=").append(value);
        } else {
            builder.append(updatedQueryParams).append("&").append(key).append("=").append(value);
        }
        return builder.toString();
    }

    protected static String parseFromQueryParams(final String queryParams, final String key) {
        Validate.notNull(queryParams);
        Validate.notNull(key);
        final List<NameValuePair> params = URLEncodedUtils.parse(queryParams, StandardCharsets.UTF_8);
        for (final NameValuePair param : params) {
            if (key.equals(param.getName())) {
                return param.getValue();
            }
        }
        return null;
    }

    protected static String removeFromQueryParams(final String queryParams, final String key) {
        Validate.notNull(queryParams);
        Validate.notNull(key);
        final List<NameValuePair> params = URLEncodedUtils.parse(queryParams, StandardCharsets.UTF_8);
        final List<NameValuePair> newParams = new ArrayList<>();
        for (final NameValuePair param : params) {
            if (! key.equals(param.getName())) {
                newParams.add(param);
            }
        }
        final String newQueryStringEncoded = URLEncodedUtils.format(newParams, StandardCharsets.UTF_8);
        try {
            final String newQueryStringDecoded = URLDecoder.decode(newQueryStringEncoded, StandardCharsets.UTF_8.toString());
            return newQueryStringDecoded;
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Failed to decode query param " + e.getLocalizedMessage());
        }
    }

}
