package com.auth0.lib;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.interfaces.RSAPublicKey;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

public class TokenVerifierTest {

    private static final String HS_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjEyMzQiLCJpc3MiOiJodHRwczovL21lLmF1dGgwLmNvbS8iLCJhdWQiOiJkYU9nbkdzUlloa3d1NjIxdmYiLCJzdWIiOiJhdXRoMHx1c2VyMTIzIn0.a7ayNmFTxS2D-EIoUikoJ6dck7I8veWyxnje_mYD3qY";
    private static final String RS_JWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjEyMzQiLCJpc3MiOiJodHRwczovL21lLmF1dGgwLmNvbS8iLCJhdWQiOiJkYU9nbkdzUlloa3d1NjIxdmYiLCJzdWIiOiJhdXRoMHx1c2VyMTIzIn0.E2oVTdApHC8GB4lWBLKWY1JJYJGlnbTTjwAogDr2lpixOfzNFeirvkk2x8p16HU6tlgXR3V2JbZRq3sL4gOflaTerL29PpZ-ksb06Dt9DOyAba91_B2aktjh1Fdiyy0h9OrQbefQdfYejD_Ad5st5C9KhG8NY4kd4IzfO9HBoj5fHR6s2RZyU3CZyJ0M5q6zxGy5JTeqyC6ghP3dNb7Ve9L32xs748fuvrEzFTWWXonQqmZH84qP75fYKzrcltlyrk6LhEujHxVic0XprL9tLypc7Xl-m2BrTxHq4n0UtgffgcrPO7sBr4NqFo6X4ZTvQV3zChWm7OZfpbDavdxxHA";
    private static final String RS_PUBLIC_KEY = "src/test/resources/public_key.pem";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldPassHSVerification() throws Exception {
        TokenVerifier verifier = new TokenVerifier("secret", "daOgnGsRYhkwu621vf", "https://me.auth0.com/");
        String id = verifier.verifyNonce(HS_JWT, "1234");

        assertThat(id, is("auth0|user123"));
    }

    @Test
    public void shouldParseHSDomainUrl() throws Exception {
        TokenVerifier verifier = new TokenVerifier("secret", "daOgnGsRYhkwu621vf", "me.auth0.com");
        String id = verifier.verifyNonce(HS_JWT, "1234");

        assertThat(id, is("auth0|user123"));
    }

    @Test
    public void shouldFailHSVerificationOnNullToken() throws Exception {
        exception.expect(NullPointerException.class);
        TokenVerifier verifier = new TokenVerifier("secret", "daOgnGsRYhkwu621vf", "https://me.auth0.com/");
        verifier.verifyNonce(null, "nonce");
    }

    @Test
    public void shouldFailHSVerificationOnNullNonce() throws Exception {
        exception.expect(NullPointerException.class);
        TokenVerifier verifier = new TokenVerifier("secret", "daOgnGsRYhkwu621vf", "https://me.auth0.com/");
        verifier.verifyNonce(HS_JWT, null);
    }

    @Test
    public void shouldFailHSVerificationOnInvalidNonce() throws Exception {
        TokenVerifier verifier = new TokenVerifier("secret", "daOgnGsRYhkwu621vf", "https://me.auth0.com/");
        String id = verifier.verifyNonce(HS_JWT, "nonce");

        assertThat(id, is(nullValue()));
    }

    @Test
    public void shouldFailHSVerificationOnInvalidAudience() throws Exception {
        TokenVerifier verifier = new TokenVerifier("secret", "someone-else", "https://me.auth0.com/");
        String id = verifier.verifyNonce(HS_JWT, "1234");

        assertThat(id, is(nullValue()));
    }

    @Test
    public void shouldFailHSVerificationOnInvalidIssuer() throws Exception {
        TokenVerifier verifier = new TokenVerifier("secret", "daOgnGsRYhkwu621vf", "https://www.google.com/");
        String id = verifier.verifyNonce(HS_JWT, "1234");

        assertThat(id, is(nullValue()));
    }


    //RS

    @Test
    public void shouldPassRSVerification() throws Exception {
        RSAPublicKey key = RequestProcessorFactory.readPublicKeyFromFile(RS_PUBLIC_KEY);
        TokenVerifier verifier = new TokenVerifier(key, "daOgnGsRYhkwu621vf", "https://me.auth0.com/");
        String id = verifier.verifyNonce(RS_JWT, "1234");

        assertThat(id, is("auth0|user123"));
    }

    @Test
    public void shouldParseRSDomainUrl() throws Exception {
        RSAPublicKey key = RequestProcessorFactory.readPublicKeyFromFile(RS_PUBLIC_KEY);
        TokenVerifier verifier = new TokenVerifier(key, "daOgnGsRYhkwu621vf", "me.auth0.com");
        String id = verifier.verifyNonce(RS_JWT, "1234");

        assertThat(id, is("auth0|user123"));
    }

    @Test
    public void shouldFailRSVerificationOnNullToken() throws Exception {
        exception.expect(NullPointerException.class);
        RSAPublicKey key = RequestProcessorFactory.readPublicKeyFromFile(RS_PUBLIC_KEY);
        TokenVerifier verifier = new TokenVerifier(key, "daOgnGsRYhkwu621vf", "https://me.auth0.com/");
        verifier.verifyNonce(null, "nonce");
    }

    @Test
    public void shouldFailRSVerificationOnNullNonce() throws Exception {
        exception.expect(NullPointerException.class);
        RSAPublicKey key = RequestProcessorFactory.readPublicKeyFromFile(RS_PUBLIC_KEY);
        TokenVerifier verifier = new TokenVerifier(key, "daOgnGsRYhkwu621vf", "https://me.auth0.com/");
        verifier.verifyNonce(RS_JWT, null);
    }

    @Test
    public void shouldFailRSVerificationOnInvalidNonce() throws Exception {
        RSAPublicKey key = RequestProcessorFactory.readPublicKeyFromFile(RS_PUBLIC_KEY);
        TokenVerifier verifier = new TokenVerifier(key, "daOgnGsRYhkwu621vf", "https://me.auth0.com/");
        String id = verifier.verifyNonce(RS_JWT, "nonce");

        assertThat(id, is(nullValue()));
    }

    @Test
    public void shouldFailRSVerificationOnInvalidAudience() throws Exception {
        RSAPublicKey key = RequestProcessorFactory.readPublicKeyFromFile(RS_PUBLIC_KEY);
        TokenVerifier verifier = new TokenVerifier(key, "someone-else", "https://me.auth0.com/");
        String id = verifier.verifyNonce(RS_JWT, "1234");

        assertThat(id, is(nullValue()));
    }

    @Test
    public void shouldFailRSVerificationOnInvalidIssuer() throws Exception {
        RSAPublicKey key = RequestProcessorFactory.readPublicKeyFromFile(RS_PUBLIC_KEY);
        TokenVerifier verifier = new TokenVerifier(key, "daOgnGsRYhkwu621vf", "https://www.google.com/");
        String id = verifier.verifyNonce(RS_JWT, "1234");

        assertThat(id, is(nullValue()));
    }
}