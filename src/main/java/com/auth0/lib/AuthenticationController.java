package com.auth0.lib;

import com.auth0.jwk.JwkProvider;
import org.apache.commons.lang3.Validate;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.List;


/**
 * Base Auth0 Authenticator class
 */
@SuppressWarnings("WeakerAccess")
public class AuthenticationController {
    private final RequestProcessor requestProcessor;

    private AuthenticationController(RequestProcessor requestProcessor) {
        this.requestProcessor = requestProcessor;
    }

    /**
     * Create a new instance that will handle both Code Grant and Implicit Grant flows using either Code Exchange or verifying the token's signature with HS256 algorithm.
     *
     * @param domain       the Auth0 domain
     * @param clientId     the Auth0 client id
     * @param clientSecret the Auth0 client secret
     * @param responseType the response type to request and handle. Must contain either 'code' or 'token' at least.
     * @return a new instance of AuthenticationController.
     * @throws UnsupportedEncodingException if the Implicit Grant is going to be used and the environment doesn't support UTF-8 encoding.
     */
    public static AuthenticationController forHS256(String domain, String clientId, String clientSecret, String responseType) throws UnsupportedEncodingException {
        return forHS256(domain, clientId, clientSecret, responseType, new RequestProcessorFactory());
    }

    //visible for testing
    static AuthenticationController forHS256(String domain, String clientId, String clientSecret, String responseType, RequestProcessorFactory factory) throws UnsupportedEncodingException {
        return forResponseType(domain, clientId, clientSecret, responseType, null, factory);
    }

    /**
     * Create a new instance that will handle both Code Grant and Implicit Grant flows using either Code Exchange or verifying the token's signature with RS256 algorithm.
     *
     * @param domain       the Auth0 domain
     * @param clientId     the Auth0 client id
     * @param clientSecret the Auth0 client secret
     * @param responseType the response type to request and handle. Must contain either 'code' or 'token' at least.
     * @return a new instance of AuthenticationController.
     * @throws UnsupportedEncodingException if the Implicit Grant is going to be used and the environment doesn't support UTF-8 encoding.
     */
    public static AuthenticationController forRS256(String domain, String clientId, String clientSecret, String responseType, JwkProvider provider) throws UnsupportedEncodingException {
        Validate.notNull(provider);
        return forRS256(domain, clientId, clientSecret, responseType, provider, new RequestProcessorFactory());
    }

    //visible for testing
    static AuthenticationController forRS256(String domain, String clientId, String clientSecret, String responseType, JwkProvider provider, RequestProcessorFactory factory) throws UnsupportedEncodingException {
        return forResponseType(domain, clientId, clientSecret, responseType, provider, factory);
    }

    private static AuthenticationController forResponseType(String domain, String clientId, String clientSecret, String responseType, JwkProvider provider, RequestProcessorFactory factory) throws UnsupportedEncodingException {
        Validate.notNull(domain);
        Validate.notNull(clientId);
        Validate.notNull(clientSecret);
        Validate.notNull(responseType);
        responseType = responseType.trim().toLowerCase();

        List<String> types = Arrays.asList(responseType.split(" "));
        if (types.contains("code")) {
            return new AuthenticationController(factory.forCodeGrant(domain, clientId, clientSecret, responseType));
        }
        if (types.contains("token")) {
            RequestProcessor processor;
            if (provider == null) {
                processor = factory.forImplicitGrant(domain, clientId, clientSecret, responseType);
            } else {
                processor = factory.forImplicitGrant(domain, clientId, clientSecret, responseType, provider);
            }
            return new AuthenticationController(processor);
        }
        throw new IllegalArgumentException("Response Type must contain either 'code' or 'token'.");
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
     * @param request     the caller request. Used to keep the session.
     * @param redirectUri the url to call with the authentication result.
     * @return the authorize url ready to call.
     */
    public String buildAuthorizeUrl(HttpServletRequest request, String redirectUri) {
        String state = RandomStorage.secureRandomString();
        String nonce = RandomStorage.secureRandomString();
        return buildAuthorizeUrl(request, redirectUri, state, nonce);
    }

    /**
     * Builds an Auth0 Authorize Url ready to call with the given parameters.
     *
     * @param request     the caller request. Used to keep the session.
     * @param redirectUri the url to call with the authentication result.
     * @param state       a valid state value.
     * @param nonce       the nonce value that will be used if the response type contains 'id_token'. Can be null.
     * @return the authorize url ready to call.
     */
    public String buildAuthorizeUrl(HttpServletRequest request, String redirectUri, String state, String nonce) {
        Validate.notNull(request);
        Validate.notNull(redirectUri);
        Validate.notNull(state);

        RandomStorage.setSessionState(request, state);
        if (requestProcessor.getResponseType().contains("id_token") && nonce != null) {
            RandomStorage.setSessionNonce(request, nonce);
        }
        return requestProcessor.buildAuthorizeUrl(redirectUri, state, nonce);
    }

}
