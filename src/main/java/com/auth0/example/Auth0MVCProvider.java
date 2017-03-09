package com.auth0.example;

import com.auth0.lib.Auth0MVC;

import javax.servlet.ServletConfig;
import java.io.UnsupportedEncodingException;

import static com.auth0.example.ConfigUtils.readRequiredParameter;

public abstract class Auth0MVCProvider {

    public static Auth0MVC getInstance(ServletConfig config) throws UnsupportedEncodingException {
        String domain = readRequiredParameter("com.auth0.domain", config);
        String clientId = readRequiredParameter("com.auth0.client_id", config);
        String clientSecret = readRequiredParameter("com.auth0.client_secret", config);

        return Auth0MVC.forHS256(domain, clientId, clientSecret, "code");
    }
}
