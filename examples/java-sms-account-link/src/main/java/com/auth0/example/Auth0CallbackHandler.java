package com.auth0.example;

import com.auth0.*;
import us.monoid.json.JSONArray;
import us.monoid.json.JSONObject;
import us.monoid.web.JSONResource;
import us.monoid.web.Resty;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.LinkedHashMap;
import java.util.Map;

import static us.monoid.web.Resty.content;


public class Auth0CallbackHandler extends Auth0ServletCallback {

    // TODO - clean up & be more generic to handle other scenarios too.
    protected Auth0User handleAccountLink(final Auth0User user, final HttpServletRequest req, final Tokens tokens) {

        // check here whether account linking is required..
        if (Auth0UserHelper.isDropBoxAuth0User(user) && !Auth0UserHelper.isLinkedAccount(user)) {
            // Retrieve existing user from persistent session
            final HttpSession session = req.getSession();
            final Auth0User existingUser = (Auth0User) session.getAttribute("user");
            final Tokens existingTokens = (Tokens) session.getAttribute("auth0tokens");
            if (existingUser != null && Auth0UserHelper.isSmsAuth0User(existingUser))  {
                // link accounts here
                final String primaryAccountUserId = user.getUserId();
                final String primaryAccountJwt = tokens.getIdToken();
                final String secondaryAccountJwt = existingTokens.getIdToken();
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
                    if (!"dropbox".equals(primaryConnectionType)) {
                        throw new IllegalStateException("Error linking accounts - wrong primary connection type detected: " + primaryConnectionType);
                    }
                    // Just fetch updated (linked) profile using previously obtained tokens for dropbox profile
                    final Auth0User linkedUser = fetchUser(tokens);
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

    @Override
    protected boolean isValidState(final HttpServletRequest req) {
        final String stateValue = req.getParameter("state");
        try {
            final Map<String, String> pairs = splitQuery(stateValue);
            final String state = pairs.get("nonce");
            return state != null && state.equals(getNonceStorage(req).getState());
        } catch (UnsupportedEncodingException e) {
            return false;
        }
    }

    protected static Map<String, String> splitQuery(final String query) throws UnsupportedEncodingException {
        if (query == null) {
            throw new NullPointerException("query cannot be null");
        }
        final Map<String, String> query_pairs = new LinkedHashMap<>();
        final String[] pairs = query.split("&");
        for (String pair : pairs) {
            final int idx = pair.indexOf("=");
            query_pairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"),
                    URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
        }
        return query_pairs;
    }


}
