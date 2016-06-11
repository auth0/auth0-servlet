package com.auth0;


import com.auth0.authentication.result.Credentials;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.JWTVerifyException;
import org.apache.commons.codec.binary.Base64;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

/**
 * Handles interception on a secured endpoint and does JWT Verification
 * Ensures for instance expired JWT tokens are not permitted access
 * Success and Failure navigation options are also configurable
 */
public class Auth0Filter implements Filter {

    private String onFailRedirectTo;
    private JWTVerifier jwtVerifier;


    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        onFailRedirectTo = filterConfig.getInitParameter("auth0.redirect_on_authentication_error");
        final String clientSecret = filterConfig.getServletContext().getInitParameter("auth0.client_secret");
        final String clientId = filterConfig.getServletContext().getInitParameter("auth0.client_id");
        jwtVerifier = new JWTVerifier(new Base64(true).decodeBase64(clientSecret), clientId);
        if (onFailRedirectTo == null) {
            throw new IllegalArgumentException("auth0.redirect_on_authentication_error parameter of " + this.getClass().getName() + " cannot be null");
        }
    }

    protected void onSuccess(final ServletRequest req, final ServletResponse res, final FilterChain next, final Auth0User auth0User)
            throws IOException, ServletException {
        final Auth0RequestWrapper auth0RequestWrapper = new Auth0RequestWrapper((HttpServletRequest) req, auth0User);
        next.doFilter(auth0RequestWrapper, res);
    }

    protected void onReject(final HttpServletResponse res) throws IOException, ServletException {
        res.sendRedirect(onFailRedirectTo);
    }

    protected boolean tokensExist(final Tokens tokens) {
        if (tokens == null) {
            return false;
        }
        return tokens.getIdToken() != null && tokens.getAccessToken() != null;
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response,
                         final FilterChain next) throws IOException, ServletException {
        final HttpServletRequest req = (HttpServletRequest) request;
        final HttpServletResponse res = (HttpServletResponse) response;
        final Tokens tokens = SessionUtils.getTokens(req);
        if (!tokensExist(tokens)) {
            onReject(res);
            return;
        }
        try {
            jwtVerifier.verify(tokens.getIdToken());
            final Auth0User auth0User = SessionUtils.getAuth0User(req);
            onSuccess(req, res, next, auth0User);
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
