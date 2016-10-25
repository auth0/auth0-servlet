package com.auth0;

import org.apache.commons.lang3.Validate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.security.Principal;

/**
 * Permits easy access to the Auth0User object for authenticated requests
 */
public class Auth0RequestWrapper extends HttpServletRequestWrapper {

    private final HttpServletRequest realRequest;
    private final Auth0User auth0User;

    /**
     * Constructor
     * @param request the http servlet request
     * @param auth0User the auth0User object to store, and return as Principal when requested
     */
    public Auth0RequestWrapper(final HttpServletRequest request, final Auth0User auth0User) {
        super(request);
        Validate.notNull(request);
        this.realRequest = request;
        this.auth0User = auth0User;
    }

    /**
     * Returns a <code>java.security.Principal</code> object containing
     * the name of the current authenticated user.
     */
    @Override
    public Principal getUserPrincipal() {
        if (this.auth0User == null) {
            return realRequest.getUserPrincipal();
        }
        return auth0User;
    }

}