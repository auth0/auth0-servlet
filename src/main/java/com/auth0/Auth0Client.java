package com.auth0;

public interface Auth0Client {

    public Tokens getTokens(String authorizationCode, String redirectUri);

    public Auth0User getUserProfile(Tokens tokens);

}
