package com.auth0.lib;

import com.auth0.exception.Auth0Exception;
import org.apache.commons.lang3.Validate;

import javax.servlet.http.HttpServletRequest;

/**
 * Main class to handle the Authorize Redirect request.
 * It will try to parse the parameters looking for tokens or an authorization code to perform a Code Exchange against the Auth0 servers.
 * When the tokens are obtained, it will request the user id associated to them and save it in the {@link javax.servlet.http.HttpSession}.
 */
class RequestProcessor {

    //Visible for testing
    final APIClientHelper clientHelper;
    final TokenVerifier verifier;

    RequestProcessor(APIClientHelper clientHelper, TokenVerifier verifier) {
        Validate.notNull(clientHelper);
        this.clientHelper = clientHelper;
        this.verifier = verifier;
    }

    RequestProcessor(APIClientHelper clientHelper) {
        this(clientHelper, null);
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
     */
    Tokens process(HttpServletRequest req) throws IllegalStateException {
        boolean validRequest = isValidRequest(req);
        if (!validRequest) {
            throw new IllegalStateException("Invalid state or error");
        }

        Tokens tokens = tokensFromRequest(req);
        String authorizationCode = req.getParameter("code");

        String userId;
        if (authorizationCode == null && verifier == null) {
            throw new IllegalStateException("Implicit Grant not allowed.");
        } else if (verifier != null) {
            String expectedNonce = SessionUtils.removeSessionNonce(req);
            userId = verifier.verifyNonce(tokens.getIdToken(), expectedNonce);
        } else {
            String redirectUri = req.getRequestURL().toString();
            try {
                Tokens latestTokens = exchangeCodeForTokens(authorizationCode, redirectUri);
                tokens = mergeTokens(tokens, latestTokens);
                userId = fetchUserId(tokens);
            } catch (Auth0Exception e) {
                throw new IllegalStateException("Couldn't exchange the code for tokens", e);
            }
        }

        if (userId == null) {
            throw new IllegalStateException("Couldn't obtain the User Id.");
        }

        SessionUtils.setSessionUserId(req, userId);
        return tokens;
    }

    /**
     * Extract the tokens from the request parameters, present when using the Implicit Grant.
     *
     * @param req the request
     * @return a new instance of Tokens wrapping the values present in the request parameters.
     */
    private Tokens tokensFromRequest(HttpServletRequest req) {
        Long expiresIn = req.getParameter("expires_in") == null ? null : Long.parseLong(req.getParameter("expires_in"));
        return new Tokens(req.getParameter("access_token"), req.getParameter("id_token"), req.getParameter("refresh_token"), req.getParameter("token_type"), expiresIn);
    }

    /**
     * Indicates whether the request is deemed valid
     *
     * @param req the request
     * @return whether this request is deemed valid or not.
     */
    private boolean isValidRequest(HttpServletRequest req) {
        return !hasError(req) && hasValidState(req);
    }

    /**
     * Checks for the presence of an error in the request parameters
     *
     * @param req the request
     * @return whether an error was present or not.
     */
    private boolean hasError(HttpServletRequest req) {
        return req.getParameter("error") != null;
    }

    /**
     * Indicates whether the state persisted in the session matches the state value received in the request parameters.
     *
     * @param req the request
     * @return whether state matches or not.
     */
    private boolean hasValidState(HttpServletRequest req) {
        String stateFromRequest = req.getParameter("state");
        return SessionUtils.checkSessionState(req, stateFromRequest);
    }

    /**
     * Calls the {@link APIClientHelper#exchangeCodeForTokens(String, String)} to request a Code Exchange.
     *
     * @param authorizationCode the authorization code received in the login request.
     * @param redirectUri       the redirect uri sent on the login.
     * @return a new instance of Tokens wrapping the values present in the response.
     * @throws Auth0Exception if the call to the Auth0 API failed.
     */
    private Tokens exchangeCodeForTokens(String authorizationCode, String redirectUri) throws Auth0Exception {
        Validate.notNull(authorizationCode);
        Validate.notNull(redirectUri);

        return clientHelper.exchangeCodeForTokens(authorizationCode, redirectUri);
    }

    /**
     * Calls the {@link APIClientHelper#fetchUserId(String)} to request the User Id of a given token.
     *
     * @param tokens the tokens to get the user id from.
     * @return the user id
     * @throws Auth0Exception if the call to the Auth0 API failed.
     */
    private String fetchUserId(Tokens tokens) throws Auth0Exception {
        Validate.notNull(tokens.getAccessToken());

        return clientHelper.fetchUserId(tokens.getAccessToken());
    }

    /**
     * Used to keep the best version of each token. If present, latest tokens will always be better than the first ones.
     *
     * @param tokens       the first obtained tokens.
     * @param latestTokens the latest obtained tokens, preferred over the first ones.
     * @return a merged version of Tokens using the latest tokens when possible.
     */
    private Tokens mergeTokens(Tokens tokens, Tokens latestTokens) {
        String accessToken = latestTokens.getAccessToken() != null ? latestTokens.getAccessToken() : tokens.getAccessToken();
        String idToken = latestTokens.getIdToken() != null ? latestTokens.getIdToken() : tokens.getIdToken();
        String refreshToken = latestTokens.getRefreshToken() != null ? latestTokens.getRefreshToken() : tokens.getRefreshToken();
        String type = latestTokens.getType() != null ? latestTokens.getType() : tokens.getType();
        Long expiresIn = latestTokens.getExpiresIn() != null ? latestTokens.getExpiresIn() : tokens.getExpiresIn();
        return new Tokens(accessToken, idToken, refreshToken, type, expiresIn);
    }

}
