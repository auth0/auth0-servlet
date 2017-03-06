package com.auth0.lib;

import com.auth0.client.auth.AuthAPI;
import com.auth0.jwk.JwkProvider;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;


/**
 * Base Auth0 Authenticator class
 */
@SuppressWarnings("WeakerAccess")
public class Auth0MVC {
    private final RequestProcessor requestProcessor;

    /**
     * Create a new instance that will handle Code Grant flows using Code Exchange for the Token verification.
     *
     * @param domain       the Auth0 domain
     * @param clientId     the Auth0 client id
     * @param clientSecret the Auth0 client secret
     * @return a new instance of Auth0MVC that accepts Code Grant flows.
     */
    public static Auth0MVC forCodeGrant(String domain, String clientId, String clientSecret) {
        return forCodeGrant(domain, clientId, clientSecret, new RequestProcessorFactory());
    }

    static Auth0MVC forCodeGrant(String domain, String clientId, String clientSecret, RequestProcessorFactory factory) {
        AuthAPI authAPI = new AuthAPI(domain, clientId, clientSecret);
        APIClientHelper helper = new APIClientHelper(authAPI);
        return new Auth0MVC(factory.forCodeGrant(helper));
    }

    /**
     * Create a new instance that will handle Implicit Grant flows using HS256 algorithm for the Token verification.
     *
     * @param domain       the Auth0 domain
     * @param clientId     the Auth0 client id
     * @param clientSecret the Auth0 client secret to verify the token signature with.
     * @return a new instance of Auth0MVC that accepts Implicit Grant flows.
     * @throws UnsupportedEncodingException if UTF-8 encoding it's not supported by the JVM.
     */
    public static Auth0MVC forImplicitGrant(String domain, String clientId, String clientSecret) throws UnsupportedEncodingException {
        return forImplicitGrant(domain, clientId, clientSecret, new RequestProcessorFactory());
    }

    static Auth0MVC forImplicitGrant(String domain, String clientId, String clientSecret, RequestProcessorFactory factory) throws UnsupportedEncodingException {
        AuthAPI authAPI = new AuthAPI(domain, clientId, clientSecret);
        APIClientHelper helper = new APIClientHelper(authAPI);
        RequestProcessor requestProcessor = factory.forImplicitGrantHS(helper, clientSecret, domain, clientId);
        return new Auth0MVC(requestProcessor);
    }

    /**
     * Create a new instance that will handle Implicit Grant flows using RS256 algorithm for the Token verification.
     *
     * @param domain      the Auth0 domain
     * @param clientId    the Auth0 client id
     * @param jwkProvider the provider of the JWK to verify the token signature with.
     * @return a new instance of Auth0MVC that accepts Implicit Grant flows.
     */
    public static Auth0MVC forImplicitGrant(String domain, String clientId, JwkProvider jwkProvider) {
        return forImplicitGrant(domain, clientId, jwkProvider, new RequestProcessorFactory());
    }

    static Auth0MVC forImplicitGrant(String domain, String clientId, JwkProvider jwkProvider, RequestProcessorFactory factory) {
        AuthAPI authAPI = new AuthAPI(domain, clientId, "");
        APIClientHelper helper = new APIClientHelper(authAPI);
        RequestProcessor requestProcessor = factory.forImplicitGrantRS(helper, jwkProvider, domain, clientId);
        return new Auth0MVC(requestProcessor);
    }

    private Auth0MVC(RequestProcessor requestProcessor) {
        this.requestProcessor = requestProcessor;
    }

    /**
     * Entrypoint for HTTP request
     * <p>
     * 1). Responsible for validating the request and ensuring the state value in session storage matches the state value passed to this endpoint.
     * 2). Exchanging the authorization code received with this HTTP request for auth0 tokens or extracting and verifying them from the request parameters.
     * 3). Getting the user information associated to the id_token/access_token.
     * 4). Storing the user id into the session storage.
     * 5). Clearing the stored state value.
     * 6). Handling success and any failure outcomes.
     * <p>
     *
     * @param request the received request to process.
     * @return the Tokens obtained after the user authentication.
     * @throws ProcessorException if an error occurred while processing the request
     */
    public Tokens handle(HttpServletRequest request) throws ProcessorException {
        return requestProcessor.process(request);
    }
}
