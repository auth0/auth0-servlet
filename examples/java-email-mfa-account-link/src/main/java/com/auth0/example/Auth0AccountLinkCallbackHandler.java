package com.auth0.example;

import com.auth0.Auth0User;
import com.auth0.NonceStorage;
import com.auth0.RequestNonceStorage;
import com.auth0.Tokens;
import us.monoid.json.JSONArray;
import us.monoid.json.JSONObject;
import us.monoid.web.JSONResource;
import us.monoid.web.Resty;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;

import static us.monoid.web.Resty.content;


public class Auth0AccountLinkCallbackHandler extends Auth0BaseCallbackHandler {

    // TODO - clean up & be more generic to handle other scenarios too.
    protected Auth0User handleAccountLink(final Auth0User user, final HttpServletRequest req, final Tokens tokens) {
        // check here whether account linking is required..
        if (Auth0UserHelper.isDropBoxAuth0User(user) && !Auth0UserHelper.isLinkedAccount(user)) {
            // Retrieve existing user from persistent session
            final HttpSession session = req.getSession();
            final Auth0User existingUser = (Auth0User) session.getAttribute("user");
            final Tokens existingTokens = (Tokens) session.getAttribute("auth0tokens");
            if (existingUser != null && Auth0UserHelper.isEmailAuth0User(existingUser))  {
                // link accounts here
                final String primaryAccountJwt = existingTokens.getIdToken();
                final String primaryAccountUserId = existingUser.getUserId();
                final String secondaryAccountJwt = tokens.getIdToken();
                try {
                    final String encodedPrimaryAccountUserId = URLEncoder.encode(primaryAccountUserId, "UTF-8");
                    final String linkUri = getUri("/api/v2/users/") + encodedPrimaryAccountUserId + "/identities";
                    final Resty resty = createResty();
                    resty.withHeader("Authorization", "Bearer " + primaryAccountJwt);
                    final JSONObject json = new JSONObject();
                    json.put("link_with", secondaryAccountJwt);
                    final JSONResource linkedProfileInfo = resty.json(linkUri, content(json));
                    final JSONArray profileArray = linkedProfileInfo.array();
                    final JSONObject firstProfileEntry = profileArray.getJSONObject(0);
                    final String primaryConnectionType = (String) firstProfileEntry.get("connection");
                    if (!"email".equals(primaryConnectionType)) {
                        throw new IllegalStateException("Error linking accounts - wrong primary connection type detected: " + primaryConnectionType);
                    }
                    // Just fetch updated (linked) profile using previously obtained tokens for email profile
                    final Auth0User linkedUser = fetchUser(existingTokens);
                    return linkedUser;
                } catch (Exception ex) {
                    throw new IllegalStateException("Error retrieving profile information from Auth0", ex);
                }
            }
        }
        // just return the existing user
        return user;
    }

    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp)
            throws ServletException, IOException {
        if (isValidRequest(req, resp)) {
            try {
                final Tokens tokens = fetchTokens(req);
                Auth0User user = fetchUser(tokens);
                user = handleAccountLink(user, req, tokens);
                store(tokens, user, req);
                final NonceStorage nonceStorage = new RequestNonceStorage(req);
                nonceStorage.setState(null);
                onSuccess(req, resp);
            } catch (IllegalArgumentException ex) {
                onFailure(req, resp, ex);
            } catch (IllegalStateException ex) {
                onFailure(req, resp, ex);
            }
        } else {
            onFailure(req, resp, new IllegalStateException("Invalid state or error"));
        }
    }

}
