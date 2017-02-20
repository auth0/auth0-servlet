package com.auth0.lib;

import com.auth0.client.auth.AuthAPI;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import static com.auth0.lib.ServletUtils.isFlagEnabled;
import static com.auth0.lib.ServletUtils.readRequiredParameter;

/**
 * Base Auth0 Authenticator class
 */
@SuppressWarnings("WeakerAccess")
public class Auth0Servlets {
    final String domain;
    final String clientId;
    final String clientSecret;
    final String certificatePath;
    final boolean allowPost;
    final boolean useCodeGrant;

    private final RequestProcessor requestProcessor;
    private final TokensCallback callback;

    public Auth0Servlets(ServletConfig config, TokensCallback callback) throws IllegalStateException {
        this(config, callback, new RequestProcessorFactory());
    }

    //Visible for testing
    Auth0Servlets(ServletConfig config, TokensCallback callback, RequestProcessorFactory factory) throws IllegalStateException {
        this(
                readRequiredParameter("com.auth0.domain", config),
                readRequiredParameter("com.auth0.client_id", config),
                readRequiredParameter("com.auth0.client_secret", config),
                parseFilePath(config.getServletContext(), config.getInitParameter("com.auth0.certificate")),
                isFlagEnabled("com.auth0.allow_post", config),
                isFlagEnabled("com.auth0.use_implicit_grant", config),
                callback,
                factory
        );
    }

    Auth0Servlets(String domain, String clientId, String clientSecret, String certificatePath, boolean allowPost, boolean useImplicitGrant, TokensCallback callback, RequestProcessorFactory factory) throws IllegalStateException {
        this.domain = domain;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.certificatePath = certificatePath;
        this.allowPost = allowPost;
        this.useCodeGrant = !useImplicitGrant;
        this.callback = callback;

        APIClientHelper clientHelper = new APIClientHelper(new AuthAPI(domain, clientId, clientSecret));

        if (useCodeGrant) {
            requestProcessor = factory.forCodeGrant(clientHelper, callback);
            return;
        }
        if (!allowPost) {
            throw new IllegalStateException("Implicit Grant can only be used with a POST method. Enable the 'com.auth0.allow_post' parameter in the Servlet configuration and make sure to request the login with the 'response_mode=form_post' parameter.");
        }

        if (certificatePath == null) {
            try {
                requestProcessor = factory.forImplicitGrantHS(clientHelper, clientSecret, clientId, domain, callback);
            } catch (UnsupportedEncodingException e) {
                throw new IllegalStateException("Missing UTF-8 encoding support.", e);
            }
        } else {
            try {
                requestProcessor = factory.forImplicitGrantRS(clientHelper, certificatePath, clientId, domain, callback);
            } catch (Exception e) {
                throw new IllegalStateException("The PublicKey or Certificate for RS256 algorithm was invalid.", e);
            }
        }
    }

    private static String parseFilePath(ServletContext context, String virtualPath) {
        return virtualPath == null ? null : context.getRealPath(virtualPath);
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
    public void process(HttpServletRequest req, HttpServletResponse res) throws IOException {
        if (req.getMethod().equals("GET") && useCodeGrant || req.getMethod().equals("POST") && allowPost) {
            requestProcessor.process(req, res);
        } else {
            IllegalStateException e = new IllegalStateException(String.format("Request with method %s not allowed.", req.getMethod()));
            callback.onFailure(req, res, e);
        }
    }
}
