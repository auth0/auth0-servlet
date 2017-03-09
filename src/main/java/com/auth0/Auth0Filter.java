package com.auth0;

import com.auth0.lib.SessionUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.auth0.ConfigUtils.readLocalRequiredParameter;

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
     *
     * @param request  the received request
     * @param response the response to send
     * @param next     the next filter chain
     */
    @SuppressWarnings("WeakerAccess")
    protected void onSuccess(ServletRequest request, ServletResponse response, FilterChain next) throws IOException, ServletException {
        next.doFilter(request, response);
    }

    /**
     * Navigation to take when a request is rejected by this filter
     *
     * @param response the response to send
     */
    @SuppressWarnings("WeakerAccess")
    protected void onReject(HttpServletResponse response) throws IOException, ServletException {
        response.sendRedirect(onFailRedirectTo);
    }

    /**
     * Perform filter check on this request - verify the User Id is present.
     *
     * @param request  the received request
     * @param response the response to send
     * @param next     the next filter chain
     **/
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain next) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String accessToken = (String) SessionUtils.get(req, "accessToken");
        if (accessToken == null) {
            onReject(res);
            return;
        }
        onSuccess(req, res, next);
    }

    @Override
    public void destroy() {}
}