package com.auth0;

import org.apache.commons.lang3.Validate;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class Auth0Filter implements Filter {

    private String onFailRedirectTo;

    /**
     * Called by the web container to indicate to a filter that it is
     * being placed into service. Initialises configuration setup for this filter
     */
    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        onFailRedirectTo = filterConfig.getInitParameter("auth0.redirect_on_authentication_error");
        Validate.notNull(onFailRedirectTo);
    }

    /**
     * Navigation to take when a request is successful by this filter
     */
    @SuppressWarnings("WeakerAccess")
    protected void onSuccess(final ServletRequest req, final ServletResponse res, final FilterChain next) throws IOException, ServletException {
        next.doFilter(req, res);
    }

    /**
     * Navigation to take when a request is rejected by this filter
     */
    @SuppressWarnings("WeakerAccess")
    protected void onReject(final HttpServletResponse res) throws IOException, ServletException {
        res.sendRedirect(onFailRedirectTo);
    }

    /**
     * Check for existence of id token and access token
     *
     * @param tokens the tokens object
     * @return boolean whether both id token and access token exist
     */
    private boolean tokensExist(final Tokens tokens) {
        if (tokens == null) {
            return false;
        }
        return tokens.getIdToken() != null || tokens.getAccessToken() != null;
    }

    /**
     * Perform filter check on this request - verify tokens exist and verify
     * the id token is valid
     */
    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain next) throws IOException, ServletException {
        final HttpServletRequest req = (HttpServletRequest) request;
        final HttpServletResponse res = (HttpServletResponse) response;
        final Tokens tokens = SessionUtils.getTokens(req);
        if (!tokensExist(tokens)) {
            onReject(res);
            return;
        }
        onSuccess(req, res, next);
    }

    @Override
    public void destroy() {
    }
}