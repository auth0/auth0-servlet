package com.auth0;

import org.apache.commons.lang3.StringUtils;

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
    protected Auth0Client auth0Client;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        redirectOnSuccess = readParameter("auth0.redirect_on_success", config);
        redirectOnFail = readParameter("auth0.redirect_on_error", config);
        for (String param : asList("auth0.client_id", "auth0.client_secret", "auth0.domain")) {
            properties.put(param, readParameter(param, config));
        }
        final String clientId = (String) properties.get("auth0.client_id");
        final String clientSecret = (String) properties.get("auth0.client_secret");
        final String domain = (String) properties.get("auth0.domain");
        this.auth0Client = new Auth0ClientImpl(clientId, clientSecret, domain);
    }

    @Override
    public void doGet(final HttpServletRequest req, final HttpServletResponse res)
            throws IOException, ServletException {
        try {
            if (isValidRequest(req)) {
                final Tokens tokens = fetchTokens(req);
                final Auth0User auth0User = auth0Client.getUserProfile(tokens);
                store(tokens, auth0User, req);
                NonceUtils.removeNonceFromStorage(req);
                onSuccess(req, res);
            } else {
                onFailure(req, res, new IllegalStateException("Invalid state or error"));
            }
        } catch (RuntimeException ex) {
            onFailure(req, res, ex);
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

    protected void store(final Tokens tokens, final Auth0User user, final HttpServletRequest req) {
        SessionUtils.setTokens(req, tokens);
        SessionUtils.setAuth0User(req, user);
    }

    protected Tokens fetchTokens(final HttpServletRequest req) throws IOException {
        final String authorizationCode = req.getParameter("code");
        final String redirectUri = req.getRequestURL().toString();
        return auth0Client.getTokens(authorizationCode, redirectUri);
    }

    protected boolean isValidRequest(final HttpServletRequest req) throws IOException {
        return !hasError(req) && isValidState(req);
    }

    protected boolean hasError(final HttpServletRequest req) {
        return req.getParameter("error") != null;
    }

    protected boolean isValidState(final HttpServletRequest req) {
        final String stateFromRequest = req.getParameter("state");
        return NonceUtils.matchesNonceInStorage(req, stateFromRequest);
    }

    protected String readParameter(final String parameter, final ServletConfig config) {
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
