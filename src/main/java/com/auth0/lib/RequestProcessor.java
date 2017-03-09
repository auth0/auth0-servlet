package com.auth0.lib;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.json.auth.UserInfo;
import com.auth0.jwk.JwkException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.apache.commons.lang3.Validate;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;

/**
 * Main class to handle the Authorize Redirect request.
 * It will try to parse the parameters looking for tokens or an authorization code to perform a Code Exchange against the Auth0 servers.
 * When the tokens are obtained, it will request the user id associated to them and save it in the {@link javax.servlet.http.HttpSession}.
 */
class RequestProcessor {

    //Visible for testing
    final AuthAPI client;
    final String responseType;
    final TokenVerifier verifier;

    RequestProcessor(AuthAPI client, String responseType, TokenVerifier verifier) {
        Validate.notNull(client);
        Validate.notNull(responseType);
        this.client = client;
        this.responseType = responseType;
        this.verifier = verifier;
    }

    List<String> getResponseType() {
        return Arrays.asList(responseType.split(" "));
    }

    /**
     * Builds an Auth0 Authorize Url ready to call with the given parameters.
     *
     * @param redirectUri the url to call with the authentication result.
     * @param state       a valid state value.
     * @param nonce       the nonce value that will be used if the response type contains 'id_token'. Can be null.
     * @return the authorize url ready to call.
     */
    String buildAuthorizeUrl(String redirectUri, String state, String nonce) {
        String authorizeUrl = client
                .authorizeUrl(redirectUri)
                .withState(state)
                .build();

        authorizeUrl = authorizeUrl.replace("response_type=code", "response_type=" + responseType);
        if (getResponseType().contains("id_token")) {
            authorizeUrl = authorizeUrl.concat("&nonce=" + nonce);
        }
        return authorizeUrl;
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
     *
     * @throws ProcessorException if an error occurred while processing the request
     */
    Tokens process(HttpServletRequest req) throws ProcessorException {
        assertNoError(req);
        assertValidState(req);

        Tokens tokens = tokensFromRequest(req);
        String authorizationCode = req.getParameter("code");

        String userId;
        if (authorizationCode == null && verifier == null) {
            throw new ProcessorException("Authorization Code missing from the request and Implicit Grant not allowed.");
        } else if (verifier != null) {
            if (getResponseType().contains("id_token")) {
                String expectedNonce = RandomStorage.removeSessionNonce(req);
                try {
                    userId = verifier.verifyNonce(tokens.getIdToken(), expectedNonce);
                } catch (JwkException | JWTVerificationException e) {
                    throw new ProcessorException("An error occurred while trying to verify the Id Token.", e);
                }
            } else {
                try {
                    userId = fetchUserId(tokens.getAccessToken());
                } catch (Auth0Exception e) {
                    throw new ProcessorException("Couldn't verify the Access Token", e);
                }
            }
        } else {
            String redirectUri = req.getRequestURL().toString();
            try {
                Tokens latestTokens = exchangeCodeForTokens(authorizationCode, redirectUri);
                tokens = mergeTokens(tokens, latestTokens);
                userId = fetchUserId(tokens.getAccessToken());
            } catch (Auth0Exception e) {
                throw new ProcessorException("Couldn't exchange the Authorization Code for Auth0 Tokens", e);
            }
        }

        if (userId == null) {
            throw new ProcessorException("Couldn't obtain the User Id.");
        }

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
     * Checks for the presence of an error in the request parameters
     *
     * @param req the request
     * @throws ProcessorException if the request contains an error
     */
    private void assertNoError(HttpServletRequest req) throws ProcessorException {
        String error = req.getParameter("error");
        if (error != null) {
            throw new ProcessorException("The request contains an error: " + error);
        }
    }

    /**
     * Checks whether the state persisted in the session matches the state value received in the request parameters.
     *
     * @param req the request
     * @throws ProcessorException if the request contains a different state from the expected one
     */
    private void assertValidState(HttpServletRequest req) throws ProcessorException {
        String stateFromRequest = req.getParameter("state");
        boolean valid = RandomStorage.checkSessionState(req, stateFromRequest);
        if (!valid) {
            throw new ProcessorException("The request contains an invalid state");
        }
    }

    /**
     * Calls the Auth0 Authentication API to perform a Code Exchange.
     *
     * @param authorizationCode the code received on the login response.
     * @param redirectUri       the redirect uri used on login request.
     * @return a new instance of {@link Tokens} with the received credentials.
     * @throws Auth0Exception if the request to the Auth0 server failed.
     * @see AuthAPI#exchangeCode(String, String)
     */
    private Tokens exchangeCodeForTokens(String authorizationCode, String redirectUri) throws Auth0Exception {
        TokenHolder holder = client
                .exchangeCode(authorizationCode, redirectUri)
                .execute();
        return new Tokens(holder.getAccessToken(), holder.getIdToken(), holder.getRefreshToken(), holder.getTokenType(), holder.getExpiresIn());
    }

    /**
     * Calls the Auth0 Authentication API to get the User Id.
     *
     * @param accessToken the access token to get the user id for.
     * @return the user id.
     * @throws Auth0Exception if the request to the Auth0 server failed.
     * @see AuthAPI#userInfo(String)
     */
    private String fetchUserId(String accessToken) throws Auth0Exception {
        UserInfo info = client
                .userInfo(accessToken)
                .execute();
        return info.getValues().containsKey("sub") ? (String) info.getValues().get("sub") : null;
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
