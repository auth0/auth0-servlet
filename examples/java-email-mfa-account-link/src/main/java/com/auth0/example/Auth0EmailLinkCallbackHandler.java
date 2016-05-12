package com.auth0.example;

import com.auth0.Auth0User;
import com.auth0.NonceStorage;
import com.auth0.RequestNonceStorage;
import com.auth0.Tokens;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class Auth0EmailLinkCallbackHandler extends Auth0BaseCallbackHandler {

    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp)
            throws ServletException, IOException {
        if (isValidRequest(req, resp)) {
            try {
                final Tokens tokens = fetchTokens(req);
                Auth0User user = fetchUser(tokens);
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
