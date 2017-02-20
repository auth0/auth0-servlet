package com.auth0.lib;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

class RequestProcessorFactory {

    RequestProcessor forCodeGrant(APIClientHelper clientHelper, TokensCallback callback) {
        return new RequestProcessor(clientHelper, callback);
    }

    RequestProcessor forImplicitGrantHS(APIClientHelper clientHelper, String clientSecret, String clientId, String domain, TokensCallback callback) throws UnsupportedEncodingException {
        TokenVerifier verifier = new TokenVerifier(clientSecret, clientId, domain);
        return new RequestProcessor(clientHelper, verifier, callback);
    }

    RequestProcessor forImplicitGrantRS(APIClientHelper clientHelper, String certificatePath, String clientId, String domain, TokensCallback callback) throws IOException {
        TokenVerifier verifier = new TokenVerifier(ServletUtils.readPublicKeyFromFile(certificatePath), clientId, domain);
        return new RequestProcessor(clientHelper, verifier, callback);
    }
}
