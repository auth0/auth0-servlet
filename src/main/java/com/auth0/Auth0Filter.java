package com.auth0;


import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.JWTVerifyException;
import org.apache.commons.codec.binary.Base64;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public class Auth0Filter implements Filter {

    private String onFailRedirectTo;
    private JWTVerifier jwtVerifier;


    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        onFailRedirectTo = filterConfig.getInitParameter("auth0.redirect_on_authentication_error");
        final String clientSecret = filterConfig.getServletContext().getInitParameter("auth0.client_secret");
        final String clientId = filterConfig.getServletContext().getInitParameter("auth0.client_id");
        jwtVerifier = new JWTVerifier(new Base64(true).decodeBase64(clientSecret), clientId);
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
        resp.sendRedirect(request.getContextPath() + onFailRedirectTo + "?"
                + request.getQueryString());
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res,
                         FilterChain next) throws IOException, ServletException {
        final Tokens tokens = loadTokens(req, res);
        if (tokens == null || !tokens.exist()) {
            onReject(req, res, next);
            return;
        }
        try {
            final Auth0User user = loadUser(req);
            jwtVerifier.verify(tokens.getIdToken());
            onSuccess(req, res, next, user);
        } catch (InvalidKeyException e) {
            throw new Auth0Exception("InvalidKeyException thrown while decoding JWT token " + e.getLocalizedMessage());
        } catch (NoSuchAlgorithmException e) {
            throw new Auth0Exception("NoSuchAlgorithmException thrown while decoding JWT token " + e.getLocalizedMessage());
        } catch (IllegalStateException e) {
            throw new Auth0Exception("IllegalStateException thrown while decoding JWT token " + e.getLocalizedMessage());
        } catch (SignatureException e) {
            throw new Auth0Exception("SignatureExceptionn thrown while decoding JWT token " + e.getLocalizedMessage());
        } catch (IOException e) {
            throw new Auth0Exception("IOException thrown while decoding JWT token " + e.getLocalizedMessage());
        } catch (JWTVerifyException e) {
            throw new Auth0Exception("JWTVerifyException thrown while decoding JWT token " + e.getLocalizedMessage());
        }
    }

    @Override
    public void destroy() {
    }
}
