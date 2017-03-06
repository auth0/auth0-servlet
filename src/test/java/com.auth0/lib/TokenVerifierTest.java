package com.auth0.lib;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwt.exceptions.InvalidClaimException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.interfaces.RSAPublicKey;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TokenVerifierTest {

    private static final String HS_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjEyMzQiLCJpc3MiOiJodHRwczovL21lLmF1dGgwLmNvbS8iLCJhdWQiOiJkYU9nbkdzUlloa3d1NjIxdmYiLCJzdWIiOiJhdXRoMHx1c2VyMTIzIn0.a7ayNmFTxS2D-EIoUikoJ6dck7I8veWyxnje_mYD3qY";
    private static final String RS_JWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiYzEyMyJ9.eyJub25jZSI6IjEyMzQiLCJpc3MiOiJodHRwczovL21lLmF1dGgwLmNvbS8iLCJhdWQiOiJkYU9nbkdzUlloa3d1NjIxdmYiLCJzdWIiOiJhdXRoMHx1c2VyMTIzIn0.PkPWdoZNfXz8EB0SBPH83lNSOhyhdhdqYIgIwgY2nHozUnFOaUjVewlAXxP_3LBGibQ_ng4s5fEEOCJjaKBy04McryvOuL6nqb1dPQseeyxuv2zQitfrs-7kEtfeS3umywM-tV6guw9_W3nmIgaXOiYiF4WJM23ItbdCmvwdXLaf9-xHkQbRY_zEwEFbprFttKUXFbkPt6XjZ3zZwZbNZn64bx2PBiSJ2KMZAE3Lghmci-RXdhi7hXpmN30Tzze1ZsjvVeRRKNzShByKK9ZGZPmQ5yggJOXFy32ehjGkYwFMCqgMQomcGbcYhsd97huKHMHl3HOE5GDYjIq9o9oKRA";
    private static final String RS_PUBLIC_KEY = "src/test/resources/public.pem";

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
    public void shouldThrowHSVerificationOnInvalidAudience() throws Exception {
        exception.expect(InvalidClaimException.class);
        TokenVerifier verifier = new TokenVerifier("secret", "someone-else", "https://me.auth0.com/");
        verifier.verifyNonce(HS_JWT, "1234");
    }

    @Test
    public void shouldThrowHSVerificationOnInvalidIssuer() throws Exception {
        exception.expect(InvalidClaimException.class);
        TokenVerifier verifier = new TokenVerifier("secret", "daOgnGsRYhkwu621vf", "https://www.google.com/");
        verifier.verifyNonce(HS_JWT, "1234");
    }


    //RS

    @Test
    public void shouldPassRSVerification() throws Exception {
        TokenVerifier verifier = new TokenVerifier(getRSProvider(), "daOgnGsRYhkwu621vf", "https://me.auth0.com/");
        String id = verifier.verifyNonce(RS_JWT, "1234");

        assertThat(id, is("auth0|user123"));
    }

    @Test
    public void shouldParseRSDomainUrl() throws Exception {
        TokenVerifier verifier = new TokenVerifier(getRSProvider(), "daOgnGsRYhkwu621vf", "me.auth0.com");
        String id = verifier.verifyNonce(RS_JWT, "1234");

        assertThat(id, is("auth0|user123"));
    }

    @Test
    public void shouldFailRSVerificationOnNullToken() throws Exception {
        exception.expect(NullPointerException.class);
        TokenVerifier verifier = new TokenVerifier(getRSProvider(), "daOgnGsRYhkwu621vf", "https://me.auth0.com/");
        verifier.verifyNonce(null, "nonce");
    }

    @Test
    public void shouldFailRSVerificationOnNullNonce() throws Exception {
        exception.expect(NullPointerException.class);
        TokenVerifier verifier = new TokenVerifier(getRSProvider(), "daOgnGsRYhkwu621vf", "https://me.auth0.com/");
        verifier.verifyNonce(RS_JWT, null);
    }

    @Test
    public void shouldFailRSVerificationOnInvalidNonce() throws Exception {
        TokenVerifier verifier = new TokenVerifier(getRSProvider(), "daOgnGsRYhkwu621vf", "https://me.auth0.com/");
        String id = verifier.verifyNonce(RS_JWT, "nonce");

        assertThat(id, is(nullValue()));
    }

    @Test
    public void shouldThrowRSVerificationOnInvalidAudience() throws Exception {
        exception.expect(InvalidClaimException.class);
        TokenVerifier verifier = new TokenVerifier(getRSProvider(), "someone-else", "https://me.auth0.com/");
        verifier.verifyNonce(RS_JWT, "1234");
    }

    @Test
    public void shouldThrowRSVerificationOnInvalidIssuer() throws Exception {
        exception.expect(InvalidClaimException.class);
        TokenVerifier verifier = new TokenVerifier(getRSProvider(), "daOgnGsRYhkwu621vf", "https://www.google.com/");
        verifier.verifyNonce(RS_JWT, "1234");
    }

    private JwkProvider getRSProvider() throws Exception {
        JwkProvider jwkProvider = mock(JwkProvider.class);
        Jwk jwk = mock(Jwk.class);
        when(jwkProvider.get("abc123")).thenReturn(jwk);
        RSAPublicKey key = RequestProcessorFactory.readPublicKeyFromFile(RS_PUBLIC_KEY);
        when(jwk.getPublicKey()).thenReturn(key);
        return jwkProvider;
    }
}