package com.auth0.lib;

import com.auth0.client.auth.AuthAPI;
import com.auth0.jwk.JwkProvider;

import java.io.UnsupportedEncodingException;

class RequestProcessorFactory {

    RequestProcessor forCodeGrant(AuthAPI client) {
        return new RequestProcessor(client);
    }

    RequestProcessor forImplicitGrantHS(AuthAPI client, String clientSecret, String domain, String clientId) throws UnsupportedEncodingException {
        TokenVerifier verifier = new TokenVerifier(clientSecret, clientId, domain);
        return new RequestProcessor(client, verifier);
    }

    RequestProcessor forImplicitGrantRS(AuthAPI client, JwkProvider jwkProvider, String domain, String clientId) {
        TokenVerifier verifier = new TokenVerifier(jwkProvider, clientId, domain);
        return new RequestProcessor(client, verifier);
    }

}
