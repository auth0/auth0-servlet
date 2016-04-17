package com.auth0;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.security.Principal;

public class Auth0RequestWrapper extends HttpServletRequestWrapper {
    String idToken;
    HttpServletRequest realRequest;
    private Auth0User user;

    public Auth0RequestWrapper(Auth0User user, HttpServletRequest request) {
        super(request);
        this.user = user;

        this.realRequest = request;
    }

    @Override
    public Principal getUserPrincipal() {
        if (this.user == null) {
            return realRequest.getUserPrincipal();
        }

        return user;
    }

}