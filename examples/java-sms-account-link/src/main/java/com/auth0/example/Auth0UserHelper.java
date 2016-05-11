package com.auth0.example;

import com.auth0.Auth0User;

public class Auth0UserHelper {

    public static boolean isLinkedAccount(final Auth0User auth0User) {
        //TODO - consider cleaner check here. is_paired attribute?
        return auth0User.getIdentities() != null && auth0User.getIdentities().length() > 1;
    }

    public static boolean isSmsAuth0User(final Auth0User auth0User) {
        return isUserType(auth0User, "sms");
    }

    public static boolean isDropBoxAuth0User(final Auth0User auth0User) {
        return isUserType(auth0User, "dropbox");
    }

    protected static boolean isUserType(final Auth0User auth0User, final String type) {
        return auth0User.getUserId().startsWith(type);
    }

}
