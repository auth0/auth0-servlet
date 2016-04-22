package com.auth0.example;

import com.auth0.*;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;

import static java.util.Arrays.asList;

/**
 * Custom Auth0ServletCallback to handle SSO interaction
 * both for portal logins and handling partner site logins
 */
public class Auth0CallbackHandler extends Auth0ServletCallback {

    protected List trustedExternalReturnUrls;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        redirectOnSuccess = readParameter("auth0.redirect_on_success", config);
        redirectOnFail = readParameter("auth0.redirect_on_error", config);
        final String trustedExternalReturnUrlsStr = readParameter("auth0.trustedExternalReturnUrls", config);
        trustedExternalReturnUrls = Arrays.asList(trustedExternalReturnUrlsStr.split("\\s*,\\s*"));
        for (String param : asList("auth0.client_id", "auth0.client_secret", "auth0.domain")) {
            properties.put(param, readParameter(param, config));
        }
    }

    protected static String readParameter(String parameter, ServletConfig config) {
        String first = config.getInitParameter(parameter);
        if (hasValue(first)) {
            return first;
        }
        final String second = config.getServletContext().getInitParameter(
                parameter);
        if (hasValue(second)) {
            return second;
        }
        throw new IllegalArgumentException(parameter + " needs to be defined");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        if (isValidRequest(req, resp)) {
            try {
                final Tokens tokens = fetchTokens(req);
                final Auth0User user = fetchUser(tokens);
                store(tokens, user, req);
                final NonceStorage nonceStorage = new RequestNonceStorage(req);
                nonceStorage.setState(null);
                onSuccess(req, resp);
            } catch (IllegalArgumentException ex) {
                onFailure(req, resp, ex);
            } catch (IllegalStateException ex) {
                onFailure(req, resp, ex);
            }
        } else {
            onFailure(req, resp, new IllegalStateException("Invalid state or error"));
        }
    }

    @Override
    protected void onSuccess(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        final String externalReturnUrl = (String) req.getAttribute("externalReturnUrl");
        if (externalReturnUrl != null) {
            resp.sendRedirect(externalReturnUrl);
        } else {
            resp.sendRedirect(req.getContextPath() + redirectOnSuccess);
        }
    }

    @Override
    protected void onFailure(HttpServletRequest req, HttpServletResponse resp, Exception ex) throws ServletException, IOException {
        ex.printStackTrace();
        final boolean hasQueryParams = req.getQueryString() != null;
        final String externalReturnUrl = (String) req.getAttribute("externalReturnUrl");
        if (externalReturnUrl != null) {
            //TODO - improve error reporting
            final String errorQueryParam = "error=CallbackFailure";
            final String redirectExternalOnFailLocation = hasQueryParams ?
                    externalReturnUrl + "?" + req.getQueryString() + "&" + errorQueryParam :
                    externalReturnUrl + "?" + errorQueryParam;
            resp.sendRedirect(redirectExternalOnFailLocation);
        } else {
            String redirectOnFailLocation = req.getContextPath() + redirectOnFail;
            if (hasQueryParams) {
                redirectOnFailLocation = redirectOnFailLocation + "?" + req.getQueryString();
            }
            resp.sendRedirect(redirectOnFailLocation);
        }
    }

    @Override
    protected boolean isValidState(HttpServletRequest req) {
        final String stateValue = req.getParameter("state");
        try {
            final Map<String, String> pairs = splitQuery(stateValue);
            final String externalReturnUrl = pairs.get("eru");
            final String state = pairs.get("nonce");
            if (externalReturnUrl != null) {
                req.setAttribute("externalReturnUrl", externalReturnUrl);
            }
            final boolean trusted = externalReturnUrl == null || isTrustedExternalReturnUrl(externalReturnUrl);
            return state != null && state.equals(getNonceStorage(req).getState()) && trusted;
        } catch (UnsupportedEncodingException e) {
            return false;
        }
    }

    protected boolean isTrustedExternalReturnUrl (final String url) {
        return trustedExternalReturnUrls.contains(url);
    }

    protected static Map<String, String> splitQuery(String query) throws UnsupportedEncodingException {
        if (query == null) {
            throw new NullPointerException("query cannot be null");
        }
        final Map<String, String> query_pairs = new LinkedHashMap<>();
        final String[] pairs = query.split("&");
        for (String pair : pairs) {
            final int idx = pair.indexOf("=");
            query_pairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"),
                    URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
        }
        return query_pairs;
    }


}
