package com.auth0;

import java.io.Serializable;

/**
 * Holds the user's credentials returned by Auth0.
 * <ul>
 * <li><i>accessToken</i>: Access Token for Auth0 API</li>
 * <li><i>idToken</i>: Identity Token with user information</li>
 * <li><i>refreshToken</i>: Refresh Token that can be used to request new tokens without signing in again</li>
 * <li><i>type</i>: Token Type</li>
 * <li><i>expiresIn</i>: Token expiration</li>
 * </ul>
 */
@SuppressWarnings({"unused", "WeakerAccess"})
public class Tokens implements Serializable {

    private static final long serialVersionUID = 2371882820082543721L;

    private final String accessToken;
    private final String idToken;
    private final String refreshToken;
    private final String type;
    private final long expiresIn;

    /**
     * @param accessToken  access token for Auth0 API
     * @param idToken      identity token with user information
     * @param refreshToken refresh token that can be used to request new tokens without signing in again
     * @param type         token type
     * @param expiresIn    token expiration
     */
    public Tokens(String accessToken, String idToken, String refreshToken, String type, long expiresIn) {
        this.accessToken = accessToken;
        this.idToken = idToken;
        this.refreshToken = refreshToken;
        this.type = type;
        this.expiresIn = expiresIn;
    }


    public String getAccessToken() {
        return accessToken;
    }

    public String getIdToken() {
        return idToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getType() {
        return type;
    }

    public long getExpiresIn() {
        return expiresIn;
    }
}
