package com.auth0;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.auth0.ServletUtils.readLocalRequiredParameter;

/**
 * Filter class to check if a valid session exists. This will be true if the User Id is present.
 */
public class Auth0Filter implements Filter {

    private String onFailRedirectTo;

    /**
     * Called by the web container to indicate to a filter that it is being placed into service.
     * Initialises configuration setup for this filter.
     * A parameter 'com.auth0.redirect_on_authentication_error' is needed on the Local Filter scope to redirect the user
     * to the {@link Auth0RedirectServlet} when the authentication is missing.
     */
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        onFailRedirectTo = readLocalRequiredParameter("com.auth0.redirect_on_authentication_error", filterConfig);
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
     * Perform filter check on this request - verify the User Id is present.
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain next) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String userId = ServletUtils.getSessionUserId(req);
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