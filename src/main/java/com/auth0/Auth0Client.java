package com.auth0;

import com.auth0.authentication.result.UserProfile;

public interface Auth0Client {

    public Tokens getTokens(String authorizationCode, String redirectUri);

    public UserProfile getUserProfile(Tokens tokens);

}
