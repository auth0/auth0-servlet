package com.auth0;

import org.apache.commons.lang3.Validate;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Filter class to check if a session exists. This will be true if the the Auth0 User id_token or access_token is available.
 */
public class Auth0Filter implements Filter {

    private String onFailRedirectTo;

    /**
     * Called by the web container to indicate to a filter that it is being placed into service.
     * Initialises configuration setup for this filter
     */
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        onFailRedirectTo = filterConfig.getInitParameter("com.auth0.redirect_on_authentication_error");
        Validate.notNull(onFailRedirectTo);
    }

    /**
     * Navigation to take when a request is successful by this filter
     */
    @SuppressWarnings("WeakerAccess")
    protected void onSuccess(ServletRequest req, ServletResponse res, FilterChain next) throws IOException, ServletException {
        next.doFilter(req, res);
    }

    /**
     * Navigation to take when a request is rejected by this filter
     */
    @SuppressWarnings("WeakerAccess")
    protected void onReject(HttpServletResponse res) throws IOException, ServletException {
        res.sendRedirect(onFailRedirectTo);
    }

    /**
     * Perform filter check on this request - verify tokens exist
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain next) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String userId = SessionUtils.getAuth0UserId(req);
        if (userId == null) {
            onReject(res);
            return;
        }
        onSuccess(req, res, next);
    }

    @Override
    public void destroy() {
    }
}