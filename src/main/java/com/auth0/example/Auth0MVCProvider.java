package com.auth0.example;

import com.auth0.lib.AuthenticationController;

import javax.servlet.ServletConfig;
import java.io.UnsupportedEncodingException;

import static com.auth0.example.ConfigUtils.readRequiredParameter;

public abstract class Auth0MVCProvider {

    public static AuthenticationController getInstance(ServletConfig config) throws UnsupportedEncodingException {
        String domain = readRequiredParameter("com.auth0.domain", config);
        String clientId = readRequiredParameter("com.auth0.client_id", config);
        String clientSecret = readRequiredParameter("com.auth0.client_secret", config);

        return AuthenticationController.newBuilder(domain, clientId, clientSecret).build();
    }
}
