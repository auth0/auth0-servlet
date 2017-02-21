package com.auth0.lib;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.json.auth.UserInfo;
import org.apache.commons.lang3.Validate;

/**
 * Wrapper for the Auth0 {@link AuthAPI} calls needed by the servlet.
 */
public class APIClientHelper {

    private final AuthAPI client;

    public APIClientHelper(AuthAPI client) {
        this.client = client;
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
    Tokens exchangeCodeForTokens(String authorizationCode, String redirectUri) throws Auth0Exception {
        Validate.notNull(authorizationCode);
        Validate.notNull(redirectUri);

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
    String fetchUserId(String accessToken) throws Auth0Exception {
        Validate.notNull(accessToken);

        UserInfo info = client
                .userInfo(accessToken)
                .execute();
        return info.getValues().containsKey("sub") ? (String) info.getValues().get("sub") : null;
    }

}
