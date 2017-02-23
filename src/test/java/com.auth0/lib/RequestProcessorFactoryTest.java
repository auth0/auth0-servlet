package com.auth0.lib;

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

public class RequestProcessorFactoryTest {

    private static final String RS_CERTIFICATE = "src/test/resources/certificate.pem";
    private static final String RS_PUBLIC_KEY = "src/test/resources/public_key.pem";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Mock
    private APIClientHelper clientHelper;
    @Mock
    private TokensCallback callback;
    private RequestProcessorFactory factory;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        factory = new RequestProcessorFactory();
    }

    @Test
    public void shouldCreateForCodeGrant() throws Exception {
        RequestProcessor processor = factory.forCodeGrant(clientHelper, callback);
        assertThat(processor, is(notNullValue()));
        assertThat(processor.clientHelper, is(clientHelper));
        assertThat(processor.verifier, is(nullValue()));
        assertThat(processor.callback, is(callback));
    }

    @Test
    public void shouldCreateForImplicitGrantHS() throws Exception {
        RequestProcessor processor = factory.forImplicitGrantHS(clientHelper, "clientSecret", "domain", "clientId", callback);
        assertThat(processor, is(notNullValue()));
        assertThat(processor.clientHelper, is(clientHelper));
        assertThat(processor.verifier, is(notNullValue()));
        assertThat(processor.callback, is(callback));
    }

    @Test
    public void shouldCreateForImplicitGrantRS() throws Exception {
        RequestProcessor processor = factory.forImplicitGrantRS(clientHelper, RS_PUBLIC_KEY, "domain", "clientId", callback);
        assertThat(processor, is(notNullValue()));
        assertThat(processor.clientHelper, is(clientHelper));
        assertThat(processor.verifier, is(notNullValue()));
        assertThat(processor.callback, is(callback));
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