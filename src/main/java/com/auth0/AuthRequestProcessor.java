package com.auth0;

import com.auth0.exception.Auth0Exception;
import org.apache.commons.lang3.Validate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

class AuthRequestProcessor {

    private final APIClientHelper clientHelper;
    private final TokensCallback callback;

    public AuthRequestProcessor(APIClientHelper clientHelper, TokensCallback callback) {
        Validate.notNull(clientHelper);
        Validate.notNull(callback);
        this.clientHelper = clientHelper;
        this.callback = callback;
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
     * @throws Auth0Exception
     * @throws IOException
     */
    public void process(HttpServletRequest req, HttpServletResponse res) throws IOException {
        boolean validRequest = isValidRequest(req);
        SessionUtils.removeState(req);
        if (!validRequest) {
            callback.onFailure(req, res, new IllegalStateException("Invalid state or error"));
            return;
        }

        Tokens tokens = tokensFromRequest(req);
        String authorizationCode = req.getParameter("code");
        if (authorizationCode != null) {
            String redirectUri = req.getRequestURL().toString();
            Tokens latestTokens = exchangeCodeForTokens(authorizationCode, redirectUri);
            tokens = mergeTokens(tokens, latestTokens);
        }

        String userId = fetchUserId(tokens);
        if (userId == null) {
            callback.onFailure(req, res, new IllegalStateException("Couldn't obtain the User Id."));
            return;
        }

        SessionUtils.setAuth0UserId(req, userId);
        callback.onSuccess(req, res, tokens);
    }

    private Tokens tokensFromRequest(HttpServletRequest req) throws Auth0Exception {
        Long expiresIn = req.getParameter("expires_in") == null ? null : Long.parseLong(req.getParameter("expires_in"));
        return new Tokens(req.getParameter("access_token"), req.getParameter("id_token"), req.getParameter("refresh_token"), req.getParameter("token_type"), expiresIn);
    }

    private Tokens exchangeCodeForTokens(String authorizationCode, String redirectUri) throws Auth0Exception {
        Validate.notNull(authorizationCode);
        Validate.notNull(redirectUri);

        return clientHelper.exchangeCodeForTokens(authorizationCode, redirectUri);
    }

    /**
     * Indicates whether the request is deemed valid
     *
     * @param req the http servlet request
     * @return boolean whether this request is deemed valid
     */
    private boolean isValidRequest(HttpServletRequest req) {
        return !hasError(req) && hasValidState(req);
    }

    /**
     * Checks for the presence of an error in the http servlet request params
     *
     * @param req the http servlet request
     * @return boolean whether this http servlet request indicates an error was present
     */
    private boolean hasError(HttpServletRequest req) {
        return req.getParameter("error") != null;
    }

    /**
     * Indicates whether the state value in storage matches the state value passed
     * with the http servlet request
     *
     * @param req the http servlet request
     * @return boolean whether state value in storage matches the state value in the http request
     */
    private boolean hasValidState(HttpServletRequest req) {
        String stateFromRequest = req.getParameter("state");
        String stateFromStorage = SessionUtils.getState(req);
        return stateFromRequest != null && stateFromRequest.equals(stateFromStorage);
    }

    private String fetchUserId(Tokens tokens) throws Auth0Exception {
        Validate.notNull(tokens.getAccessToken());

        return clientHelper.fetchUserId(tokens.getAccessToken());
    }

    /**
     * Used to keep the best version of each token included in Tokens.
     *
     * @param tokens       the first obtained tokens.
     * @param latestTokens the latest obtained tokens, usually better than the first.
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
