package com.auth0.example;

import com.auth0.Auth0User;
import us.monoid.json.JSONArray;
import us.monoid.json.JSONException;
import us.monoid.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

public class Auth0UserHelper {

    public static boolean isLinkedAccount(final Auth0User auth0User) {
        //TODO - consider cleaner check here. is_paired attribute?
        return auth0User.getIdentities() != null && auth0User.getIdentities().length() > 1;
    }

    public static boolean isEmailAuth0User(final Auth0User auth0User) {
        return isUserType(auth0User, "email");
    }

    public static boolean isMfaEnabled(final Auth0User auth0User) {
        try {
            final JSONObject appMetadata = auth0User.getAppMetadata();
            if (appMetadata.isNull("mfa")) {
                return false;
            }
            final Boolean mfa = (Boolean) appMetadata.get("mfa");
            return mfa != null && mfa;
        } catch (Exception e) {
            throw new IllegalStateException("Error retrieving mfa information from Auth0", e);
        }
    }

    public static boolean isDropBoxAuth0User(final Auth0User auth0User) {
        return isUserType(auth0User, "dropbox");
    }

    protected static boolean isUserType(final Auth0User auth0User, final String type) {
        return auth0User.getUserId().startsWith(type);
    }

    public static List<String> getLinkedAccountsInfo(final Auth0User auth0User) {
        //TODO - clean up - this is hacky.. working with an awkward JSON lib
        final JSONArray identitiesArray = auth0User.getIdentities();
        final List<String> linkedAccounts = new ArrayList<>();
        if (identitiesArray.isNull(1)) {
            return linkedAccounts;
        }
        try {
            int index = 1;
            while (! identitiesArray.isNull(index)) {
                final JSONObject profile = identitiesArray.getJSONObject(index);
                final StringBuffer data = new StringBuffer();
                if (!profile.isNull("provider")) {
                    final String provider = (String) profile.get("provider");
                    data.append(provider).append("|");
                }
                if (!profile.isNull("profileData") &&  !profile.getJSONObject("profileData").isNull("email"))  {
                    final String email = (String) profile.getJSONObject("profileData").get("email");
                    data.append(email);
                }
                if (data.length() > 0) {
                    linkedAccounts.add(data.toString());
                }
                index++;
            }
        } catch (JSONException e) {
            throw new IllegalStateException("Error retrieving data", e);
        }
        return linkedAccounts;
    }

}
