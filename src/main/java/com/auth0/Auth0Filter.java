package com.auth0;


import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class Auth0Filter implements Filter {

    private String onFailRedirectTo;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        onFailRedirectTo = filterConfig.getInitParameter("auth0.redirect_on_authentication_error");
        
        if (onFailRedirectTo == null) {
            throw new IllegalArgumentException("auth0.redirect_on_authentication_error parameter of " + this.getClass().getName() + " cannot be null");
        }
    }

    protected Tokens loadTokens(ServletRequest req, ServletResponse resp) {
        HttpSession session = ((HttpServletRequest) req).getSession();
        return (Tokens) session.getAttribute("auth0tokens");
    }
    
    protected Auth0User loadUser(ServletRequest req) {
        HttpSession session = ((HttpServletRequest) req).getSession();
        return (Auth0User) session.getAttribute("user");
    }

    protected void onSuccess(ServletRequest req, ServletResponse resp, FilterChain next, Auth0User user) throws IOException, ServletException {
        Auth0RequestWrapper auth0RequestWrapper = new Auth0RequestWrapper(user, (HttpServletRequest) req);
        next.doFilter(auth0RequestWrapper, resp);
    }

    protected void onReject(ServletRequest req, ServletResponse response, FilterChain next) throws IOException, ServletException {
        HttpServletResponse resp = (HttpServletResponse) response;
        HttpServletRequest request = (HttpServletRequest) req;
        String queryString = request.getQueryString() == null ? "" : "?" + request.getQueryString();
        resp.sendRedirect(request.getContextPath() + onFailRedirectTo + queryString);
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse resp,
                         FilterChain next) throws IOException, ServletException {

        Tokens tokens = loadTokens(req, resp);
        Auth0User user = loadUser(req);

        // Reject if not accessToken or idToken are found
        if (tokens == null || !tokens.exist()) {
            onReject(req, resp, next);
            return;
        }

        onSuccess(req, resp, next, user);
    }

    @Override
    public void destroy() {
    }
}
