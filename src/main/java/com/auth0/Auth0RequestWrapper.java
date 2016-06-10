package com.auth0;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.security.Principal;

/**
 * Permits easy access to the Auth0User object for authenticated requests
 */
public class Auth0RequestWrapper extends HttpServletRequestWrapper {

    private final HttpServletRequest realRequest;
    private final Auth0User auth0User;

    public Auth0RequestWrapper(final HttpServletRequest request, final Auth0User auth0User) {
        super(request);
        this.realRequest = request;
        this.auth0User = auth0User;
    }

    @Override
    public Principal getUserPrincipal() {
        if (this.auth0User == null) {
            return realRequest.getUserPrincipal();
        }
        return auth0User;
    }

}