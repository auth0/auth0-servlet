package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.json.auth.UserInfo;
import org.apache.commons.lang3.Validate;

class APIClientHelper {

    private final AuthAPI client;

    public APIClientHelper(AuthAPI client) {
        this.client = client;
    }


    public Tokens exchangeCodeForTokens(String authorizationCode, String redirectUri) throws Auth0Exception {
        Validate.notNull(authorizationCode);
        Validate.notNull(redirectUri);

        TokenHolder holder = client
                .exchangeCode(authorizationCode, redirectUri)
                .execute();
        return new Tokens(holder.getAccessToken(), holder.getIdToken(), holder.getRefreshToken(), holder.getTokenType(), holder.getExpiresIn());
    }


    public String fetchUserId(String accessToken) throws Auth0Exception {
        Validate.notNull(accessToken);

        UserInfo info = client
                .userInfo(accessToken)
                .execute();
        return info.getValues().containsKey("sub") ? (String) info.getValues().get("sub") : null;
    }

}
