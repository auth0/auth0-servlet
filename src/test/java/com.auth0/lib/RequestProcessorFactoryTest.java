package com.auth0.lib;

import com.auth0.jwk.JwkProvider;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

public class RequestProcessorFactoryTest {

    private static final String RS_CERTIFICATE = "src/test/resources/certificate.pem";
    private static final String RS_PUBLIC_KEY = "src/test/resources/public.pem";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Mock
    private APIClientHelper clientHelper;
    private RequestProcessorFactory factory;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        factory = new RequestProcessorFactory();
    }

    @Test
    public void shouldCreateForCodeGrant() throws Exception {
        RequestProcessor processor = factory.forCodeGrant(clientHelper);
        assertThat(processor, is(notNullValue()));
        assertThat(processor.clientHelper, is(clientHelper));
        assertThat(processor.verifier, is(nullValue()));
    }

    @Test
    public void shouldCreateForImplicitGrantHS() throws Exception {
        RequestProcessor processor = factory.forImplicitGrantHS(clientHelper, "clientSecret", "domain", "clientId");
        assertThat(processor, is(notNullValue()));
        assertThat(processor.clientHelper, is(clientHelper));
        assertThat(processor.verifier, is(notNullValue()));
    }

    @Test
    public void shouldCreateForImplicitGrantRS() throws Exception {
        JwkProvider jwkProvider = mock(JwkProvider.class);
        RequestProcessor processor = factory.forImplicitGrantRS(clientHelper, jwkProvider, "domain", "clientId");
        assertThat(processor, is(notNullValue()));
        assertThat(processor.clientHelper, is(clientHelper));
        assertThat(processor.verifier, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnReadRSAKeyWithNullPath() throws Exception {
        exception.expect(NullPointerException.class);
        RequestProcessorFactory.readPublicKeyFromFile(null);
    }

    @Test
    public void shouldThrowOnReadRSAKeyFromMissingFile() throws Exception {
        exception.expect(IOException.class);
        exception.expectMessage("Couldn't parse the RSA Public Key / Certificate file.");
        RequestProcessorFactory.readPublicKeyFromFile("/not/existing/file");
    }

    @Test
    public void shouldReadRSAKeyFromPublicKeyFile() throws Exception {
        RSAPublicKey key = RequestProcessorFactory.readPublicKeyFromFile(RS_PUBLIC_KEY);
        assertThat(key, is(notNullValue()));
    }

    @Test
    public void shouldReadRSAKeyFromCertificateFile() throws Exception {
        RSAPublicKey key = RequestProcessorFactory.readPublicKeyFromFile(RS_CERTIFICATE);
        assertThat(key, is(notNullValue()));
    }

}