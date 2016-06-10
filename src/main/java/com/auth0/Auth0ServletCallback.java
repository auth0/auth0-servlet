package com.auth0;

import com.auth0.authentication.AuthenticationAPIClient;
import com.auth0.authentication.result.Credentials;
import com.auth0.authentication.result.UserProfile;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Properties;

import static java.util.Arrays.asList;

public class Auth0ServletCallback extends HttpServlet {

    protected Properties properties = new Properties();
    protected String redirectOnSuccess;
    protected String redirectOnFail;
    protected AuthenticationAPIClient authenticationAPIClient;


    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        redirectOnSuccess = readParameter("auth0.redirect_on_success", config);
        redirectOnFail = readParameter("auth0.redirect_on_error", config);
        for (String param : asList("auth0.client_id", "auth0.client_secret", "auth0.domain")) {
            properties.put(param, readParameter(param, config));
        }
        if (authenticationAPIClient == null) {
            final String clientId = (String) properties.get("auth0.client_id");
            final String clientSecret = (String) properties.get("auth0.client_secret");
            final String domain = (String) properties.get("auth0.domain");
            final Auth0 auth0 = new Auth0(clientId, clientSecret, domain);
            authenticationAPIClient = new AuthenticationAPIClient(auth0);
        }
    }

    @Override
    public void doGet(final HttpServletRequest req, final HttpServletResponse res)
            throws IOException, ServletException {
        if (isValidRequest(req)) {
            try {
                final Credentials tokens = fetchTokens(req);
                final UserProfile userProfile = fetchUserProfile(tokens);
                store(tokens, new Auth0User(userProfile), req);
                NonceUtils.removeNonceFromStorage(req);
                onSuccess(req, res);
            } catch (IllegalArgumentException ex) {
                onFailure(req, res, ex);
            } catch (IllegalStateException ex) {
                onFailure(req, res, ex);
            }
        } else {
            onFailure(req, res, new IllegalStateException("Invalid state or error"));
        }
    }

    protected void onSuccess(final HttpServletRequest req, final HttpServletResponse res)
            throws ServletException, IOException {
        res.sendRedirect(req.getContextPath() + redirectOnSuccess);
    }

    protected void onFailure(final HttpServletRequest req, final HttpServletResponse res,
                             Exception ex) throws ServletException, IOException {
        ex.printStackTrace();
        final String redirectOnFailLocation = req.getContextPath() + redirectOnFail;
        res.sendRedirect(redirectOnFailLocation);
    }

    protected void store(final Credentials tokens, final Auth0User user, final HttpServletRequest req) {
        SessionUtils.setTokens(req, tokens);
        SessionUtils.setAuth0User(req, user);
    }

    protected Credentials fetchTokens(final HttpServletRequest req) throws IOException {
        final String authorizationCode = getAuthorizationCode(req);
        final String redirectUri = req.getRequestURL().toString();
        final String clientSecret = (String) properties.get("auth0.client_secret");
        try {
            final Credentials credentials = authenticationAPIClient
                    .token(authorizationCode, redirectUri)
                    .setClientSecret(clientSecret).execute();
            return credentials;
        } catch (Auth0Exception e) {
            throw new IllegalStateException("Cannot get Token from Auth0", e);
        }
    }

    protected UserProfile fetchUserProfile(final Credentials tokens) {
        final String idToken = tokens.getIdToken();
        try {
            final UserProfile profile = authenticationAPIClient.tokenInfo(idToken).execute();
            return profile;
        } catch (Exception ex) {
            throw new IllegalStateException("Cannot get Auth0User from Auth0", ex);
        }
    }

    protected String getAuthorizationCode(final HttpServletRequest req) {
        final String code = req.getParameter("code");
        Validate.notNull(code);
        return code;
    }

    protected boolean isValidRequest(final HttpServletRequest req) throws IOException {
        if (hasError(req)) {
            return false;
        }
        final String stateFromRequest = req.getParameter("state");
        return NonceUtils.matchesNonceInStorage(req, stateFromRequest);
    }

    protected static boolean hasError(final HttpServletRequest req) {
        return req.getParameter("error") != null;
    }

    protected static String readParameter(final String parameter, final ServletConfig config) {
        final String initParam = config.getInitParameter(parameter);
        if (StringUtils.isNotEmpty(initParam)) {
            return initParam;
        }
        final String servletContextInitParam = config.getServletContext().getInitParameter(parameter);
        if (StringUtils.isNotEmpty(servletContextInitParam)) {
            return servletContextInitParam;
        }
        throw new IllegalArgumentException(parameter + " needs to be defined");
    }

}
