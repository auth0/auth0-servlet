package com.auth0;

import org.bouncycastle.util.io.pem.PemReader;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.io.StringReader;
import java.security.interfaces.RSAKey;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

public class TokenVerifierTest {

    private static final String HS_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjEyMzQiLCJpc3MiOiJodHRwczovL21lLmF1dGgwLmNvbS8iLCJhdWQiOiJkYU9nbkdzUlloa3d1NjIxdmYiLCJzdWIiOiJhdXRoMHx1c2VyMTIzIn0.a7ayNmFTxS2D-EIoUikoJ6dck7I8veWyxnje_mYD3qY";
    private static final String RS_JWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjEyMzQiLCJpc3MiOiJodHRwczovL21lLmF1dGgwLmNvbS8iLCJhdWQiOiJkYU9nbkdzUlloa3d1NjIxdmYiLCJzdWIiOiJhdXRoMHx1c2VyMTIzIn0.E2oVTdApHC8GB4lWBLKWY1JJYJGlnbTTjwAogDr2lpixOfzNFeirvkk2x8p16HU6tlgXR3V2JbZRq3sL4gOflaTerL29PpZ-ksb06Dt9DOyAba91_B2aktjh1Fdiyy0h9OrQbefQdfYejD_Ad5st5C9KhG8NY4kd4IzfO9HBoj5fHR6s2RZyU3CZyJ0M5q6zxGy5JTeqyC6ghP3dNb7Ve9L32xs748fuvrEzFTWWXonQqmZH84qP75fYKzrcltlyrk6LhEujHxVic0XprL9tLypc7Xl-m2BrTxHq4n0UtgffgcrPO7sBr4NqFo6X4ZTvQV3zChWm7OZfpbDavdxxHA";
    private static final String RS_CERT = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuGbXWiK3dQTyCbX5xdE4\n" +
            "yCuYp0AF2d15Qq1JSXT/lx8CEcXb9RbDddl8jGDv+spi5qPa8qEHiK7FwV2KpRE9\n" +
            "83wGPnYsAm9BxLFb4YrLYcDFOIGULuk2FtrPS512Qea1bXASuvYXEpQNpGbnTGVs\n" +
            "WXI9C+yjHztqyL2h8P6mlThPY9E9ue2fCqdgixfTFIF9Dm4SLHbphUS2iw7w1JgT\n" +
            "69s7of9+I9l5lsJ9cozf1rxrXX4V1u/SotUuNB3Fp8oB4C1fLBEhSlMcUJirz1E8\n" +
            "AziMCxS+VrRPDM+zfvpIJg3JljAh3PJHDiLu902v9w+Iplu1WyoB2aPfitxEhRN0\n" +
            "YwIDAQAB\n" +
            "-----END PUBLIC KEY-----";

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
        TokenVerifier verifier = new TokenVerifier(getRSKey(), "daOgnGsRYhkwu621vf", "https://me.auth0.com/");
        String id = verifier.verifyNonce(RS_JWT, "1234");

        assertThat(id, is("auth0|user123"));
    }

    @Test
    public void shouldParseRSDomainUrl() throws Exception {
        TokenVerifier verifier = new TokenVerifier(getRSKey(), "daOgnGsRYhkwu621vf", "me.auth0.com");
        String id = verifier.verifyNonce(RS_JWT, "1234");

        assertThat(id, is("auth0|user123"));
    }

    @Test
    public void shouldFailRSVerificationOnNullToken() throws Exception {
        exception.expect(NullPointerException.class);
        TokenVerifier verifier = new TokenVerifier(getRSKey(), "daOgnGsRYhkwu621vf", "https://me.auth0.com/");
        verifier.verifyNonce(null, "nonce");
    }

    @Test
    public void shouldFailRSVerificationOnNullNonce() throws Exception {
        exception.expect(NullPointerException.class);
        TokenVerifier verifier = new TokenVerifier(getRSKey(), "daOgnGsRYhkwu621vf", "https://me.auth0.com/");
        verifier.verifyNonce(RS_JWT, null);
    }

    @Test
    public void shouldFailRSVerificationOnInvalidNonce() throws Exception {
        TokenVerifier verifier = new TokenVerifier(getRSKey(), "daOgnGsRYhkwu621vf", "https://me.auth0.com/");
        String id = verifier.verifyNonce(RS_JWT, "nonce");

        assertThat(id, is(nullValue()));
    }

    @Test
    public void shouldFailRSVerificationOnInvalidAudience() throws Exception {
        TokenVerifier verifier = new TokenVerifier(getRSKey(), "someone-else", "https://me.auth0.com/");
        String id = verifier.verifyNonce(RS_JWT, "1234");

        assertThat(id, is(nullValue()));
    }

    @Test
    public void shouldFailRSVerificationOnInvalidIssuer() throws Exception {
        TokenVerifier verifier = new TokenVerifier(getRSKey(), "daOgnGsRYhkwu621vf", "https://www.google.com/");
        String id = verifier.verifyNonce(RS_JWT, "1234");

        assertThat(id, is(nullValue()));
    }

    private RSAKey getRSKey() throws IOException {
        byte[] keyBytes = new PemReader(new StringReader(RS_CERT)).readPemObject().getContent();
        return ServletUtils.readPublicKey(keyBytes);
    }
}