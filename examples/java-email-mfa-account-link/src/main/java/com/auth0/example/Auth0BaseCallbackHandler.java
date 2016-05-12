package com.auth0.example;

import com.auth0.Auth0ServletCallback;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.Map;


public class Auth0BaseCallbackHandler extends Auth0ServletCallback {


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
