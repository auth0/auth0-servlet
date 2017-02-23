package com.auth0.lib;

import com.auth0.client.auth.AuthAPI;
import com.auth0.jwk.JwkProvider;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;


/**
 * Base Auth0 Authenticator class
 */
@SuppressWarnings("WeakerAccess")
public class Auth0MVC {
    private final RequestProcessor requestProcessor;
    private final TokensCallback callback;
    private final boolean useImplicitGrant;

    /**
     * Create a new instance that will handle Code Grant flows using Code Exchange for the Token verification.
     *
     * @param domain   the Auth0 domain
     * @param clientId the Auth0 client id
     * @param callback the callback to notify on success or failure.
     * @throws IOException if the
     */
    public Auth0MVC(String domain, String clientId, TokensCallback callback) {
        //useImplicitGrant
        AuthAPI authAPI = new AuthAPI(domain, clientId, "");
        APIClientHelper helper = new APIClientHelper(authAPI);
        this.requestProcessor = new RequestProcessorFactory().forCodeGrant(helper, callback);
        this.callback = callback;
        this.useImplicitGrant = false;
    }

    /**
     * Create a new instance that will handle Implicit Grant flows using HS256 algorithm for the Token verification.
     *
     * @param domain       the Auth0 domain
     * @param clientId     the Auth0 client id
     * @param clientSecret the Auth0 client secret to verify the token signature with.
     * @param callback     the callback to notify on success or failure.
     * @throws IOException if the
     */
    public Auth0MVC(String domain, String clientId, String clientSecret, TokensCallback callback) throws IllegalStateException {
        //useImplicitGrant - HS256
        AuthAPI authAPI = new AuthAPI(domain, clientId, clientSecret);
        APIClientHelper helper = new APIClientHelper(authAPI);
        try {
            this.requestProcessor = new RequestProcessorFactory().forImplicitGrantHS(helper, clientSecret, domain, clientId, callback);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Couldn't create RequestProcessor for HS256 Algorithm.", e);
        }
        this.callback = callback;
        this.useImplicitGrant = true;
    }

    /**
     * Create a new instance that will handle Implicit Grant flows using RS256 algorithm for the Token verification.
     *
     * @param domain         the Auth0 domain
     * @param clientId       the Auth0 client id
     * @param jwkProvider the provider of the JWK to verify the token signature with.
     * @param callback       the callback to notify on success or failure.
     * @throws IOException if the
     */
    public Auth0MVC(String domain, String clientId, JwkProvider jwkProvider, TokensCallback callback) throws IllegalStateException {
        AuthAPI authAPI = new AuthAPI(domain, clientId, "");
        APIClientHelper helper = new APIClientHelper(authAPI);
        try {
            this.requestProcessor = new RequestProcessorFactory().forImplicitGrantRS(helper, jwkProvider, domain, clientId, callback);
        } catch (IOException e) {
            throw new IllegalStateException("Couldn't create RequestProcessor for RS256 Algorithm.", e);
        }
        this.callback = callback;
        this.useImplicitGrant = true;
    }

    /**
     * Entrypoint for HTTP request
     * <p>
     * 1). Responsible for validating the request and ensuring the state value in session storage matches the state value passed to this endpoint.
     * 2). Exchanging the authorization code received with this HTTP request for auth0 tokens.
     * 3). Getting the user information associated to the id_token/access_token.
     * 4). Storing both tokens and user information into session storage.
     * 5). Clearing the stored state value.
     * 6). Handling success and any failure outcomes.
     * <p>
     * If the HTTP method is not allowed by the Servlet configuration, {@link TokensCallback#onFailure(HttpServletRequest, HttpServletResponse, Throwable)} will be called with a {@link IllegalArgumentException}.
     *
     * @throws IOException
     */
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        if (!req.getMethod().equals("POST") && useImplicitGrant) {
            IllegalStateException e = new IllegalStateException("Implicit Grant can only be used with Http POST method");
            callback.onFailure(req, res, e);
            return;
        }
        requestProcessor.process(req, res);
    }
}
