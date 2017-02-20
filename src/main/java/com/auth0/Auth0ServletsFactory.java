package com.auth0;

import com.auth0.lib.Auth0Servlets;
import com.auth0.lib.TokensCallback;

import javax.servlet.ServletConfig;

class Auth0ServletsFactory {

    Auth0Servlets newInstance(ServletConfig config, TokensCallback callback) {
        return new Auth0Servlets(config, callback);
    }
}
