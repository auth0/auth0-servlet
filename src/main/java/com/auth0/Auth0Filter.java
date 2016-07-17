package com.auth0;


import com.auth0.jwt.Algorithm;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.JWTVerifyException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.Validate;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;

import static com.auth0.jwt.pem.PemReader.readPublicKey;

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
        Validate.notNull(onFailRedirectTo);
        final String clientId = filterConfig.getServletContext().getInitParameter("auth0.client_id");
        Validate.notNull(clientId);
        final String signingAlgorithmStr = filterConfig.getServletContext().getInitParameter("auth0.signing_algorithm");
        // default to HS256 for backwards compatibility
        final Algorithm signingAlgorithm = (signingAlgorithmStr != null) ? Algorithm.valueOf(signingAlgorithmStr) : Algorithm.HS256;
        switch (signingAlgorithm) {
            case HS256:
            case HS384:
            case HS512:
                final String clientSecret = filterConfig.getServletContext().getInitParameter("auth0.client_secret");
                Validate.notNull(clientSecret);
                jwtVerifier = new JWTVerifier(new Base64(true).decodeBase64(clientSecret), clientId);
                return;
            case RS256:
            case RS384:
            case RS512:
                final String publicKeyPath = filterConfig.getServletContext().getInitParameter("auth0.public_key_path");
                Validate.notNull(publicKeyPath);
                try {
                    final ServletContext context = filterConfig.getServletContext();
                    final String publicKeyRealPath = context.getRealPath(publicKeyPath);
                    final PublicKey publicKey = readPublicKey(publicKeyRealPath);
                    Validate.notNull(publicKey);
                    jwtVerifier = new JWTVerifier(publicKey, clientId);
                    return;
                } catch (Exception e) {
                    throw new IllegalStateException(e.getMessage(), e.getCause());
                }
            default:
                throw new IllegalStateException("Unsupported signing method: " + signingAlgorithm.getValue());
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
