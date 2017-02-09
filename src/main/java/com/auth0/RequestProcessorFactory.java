package com.auth0;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import static com.auth0.ServletUtils.readPublicKey;

class RequestProcessorFactory {

    RequestProcessor forCodeGrant(APIClientHelper clientHelper, TokensCallback callback) {
        return new RequestProcessor(clientHelper, callback);
    }

    RequestProcessor forImplicitGrantHS(APIClientHelper clientHelper, String clientSecret, String clientId, String domain, TokensCallback callback) throws UnsupportedEncodingException {
        TokenVerifier verifier = new TokenVerifier(clientSecret, clientId, domain);
        return new RequestProcessor(clientHelper, verifier, callback);
    }

    RequestProcessor forImplicitGrantRS(APIClientHelper clientHelper, byte[] keyBytes, String clientId, String domain, TokensCallback callback) throws IOException {
        TokenVerifier verifier = new TokenVerifier(readPublicKey(keyBytes), clientId, domain);
        return new RequestProcessor(clientHelper, verifier, callback);
    }
}
