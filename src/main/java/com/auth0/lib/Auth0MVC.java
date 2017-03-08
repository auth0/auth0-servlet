package com.auth0.lib;

import com.auth0.client.auth.AuthAPI;
import com.auth0.jwk.JwkProvider;
import org.apache.commons.lang3.Validate;

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
        Validate.notNull(domain);
        Validate.notNull(clientId);
        Validate.notNull(clientSecret);
        Validate.notNull(factory);

        AuthAPI client = new AuthAPI(domain, clientId, clientSecret);
        return new Auth0MVC(factory.forCodeGrant(client));
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
        Validate.notNull(domain);
        Validate.notNull(clientId);
        Validate.notNull(clientSecret);
        Validate.notNull(factory);

        AuthAPI client = new AuthAPI(domain, clientId, clientSecret);
        RequestProcessor requestProcessor = factory.forImplicitGrantHS(client, clientSecret, domain, clientId);
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
        Validate.notNull(domain);
        Validate.notNull(clientId);
        Validate.notNull(jwkProvider);
        Validate.notNull(factory);

        AuthAPI client = new AuthAPI(domain, clientId, "");
        RequestProcessor requestProcessor = factory.forImplicitGrantRS(client, jwkProvider, domain, clientId);
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
        Validate.notNull(request);

        return requestProcessor.process(request);
    }

    /**
     * Builds an Auth0 Authorize Url ready to call with the given parameters.
     *
     * @param request      the caller request. Used to keep the session.
     * @param redirectUri  the url to call with the authentication result.
     * @param responseType the response type to request. It's strongly encouraged to use 'code'.
     * @return the authorize url ready to call.
     */
    public String buildAuthorizeUrl(HttpServletRequest request, String redirectUri, String responseType) {
        String state = SessionUtils.secureRandomString();
        String nonce = SessionUtils.secureRandomString();
        return buildAuthorizeUrl(request, redirectUri, responseType, state, nonce);
    }

    /**
     * Builds an Auth0 Authorize Url ready to call with the given parameters.
     *
     * @param request      the caller request. Used to keep the session.
     * @param redirectUri  the url to call with the authentication result.
     * @param responseType the response type to request. It's strongly encouraged to use 'code'.
     * @param state        a valid state value.
     * @param nonce        the nonce value that will be used if the response type contains 'id_token'. Can be null.
     * @return the authorize url ready to call.
     */
    public String buildAuthorizeUrl(HttpServletRequest request, String redirectUri, String responseType, String state, String nonce) {
        Validate.notNull(request);
        Validate.notNull(redirectUri);
        Validate.notNull(responseType);
        Validate.notNull(state);

        SessionUtils.setSessionState(request, state);
        if (responseType.contains("id_token") && nonce != null) {
            SessionUtils.setSessionNonce(request, nonce);
        }
        return requestProcessor.buildAuthorizeUrl(redirectUri, responseType, state, nonce);
    }

}
