package com.auth0;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.apache.commons.lang3.Validate;

import java.io.UnsupportedEncodingException;
import java.security.interfaces.RSAKey;

@SuppressWarnings("WeakerAccess")
class TokenVerifier {

    private final JWTVerifier verifier;

    public TokenVerifier(String clientSecret, String clientId, String domain) throws UnsupportedEncodingException {
        this(Algorithm.HMAC256(clientSecret), clientId, toUrl(domain));
    }

    public TokenVerifier(RSAKey key, String clientId, String domain) {
        this(Algorithm.RSA256(key), clientId, toUrl(domain));
    }

    private TokenVerifier(Algorithm algorithm, String audience, String issuer) {
        Validate.notNull(algorithm);
        Validate.notNull(audience);
        Validate.notNull(issuer);
        verifier = JWT.require(algorithm)
                .withAudience(audience)
                .withIssuer(issuer)
                .build();
    }

    public String getUserId(String idToken) {
        Validate.notNull(idToken);

        try {
            return verifier.verify(idToken).getSubject();
        } catch (JWTVerificationException e) {
            return null;
        }
    }

    private static String toUrl(String domain) {
        if (domain.startsWith("http://") || domain.startsWith("https://")) {
            return domain;
        } else {
            return "https://" + domain;
        }
    }

}
