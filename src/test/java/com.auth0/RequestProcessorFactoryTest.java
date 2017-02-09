package com.auth0;

import org.bouncycastle.util.io.pem.PemReader;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.StringReader;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

public class RequestProcessorFactoryTest {

    private static final String RS_CERT = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuGbXWiK3dQTyCbX5xdE4\n" +
            "yCuYp0AF2d15Qq1JSXT/lx8CEcXb9RbDddl8jGDv+spi5qPa8qEHiK7FwV2KpRE9\n" +
            "83wGPnYsAm9BxLFb4YrLYcDFOIGULuk2FtrPS512Qea1bXASuvYXEpQNpGbnTGVs\n" +
            "WXI9C+yjHztqyL2h8P6mlThPY9E9ue2fCqdgixfTFIF9Dm4SLHbphUS2iw7w1JgT\n" +
            "69s7of9+I9l5lsJ9cozf1rxrXX4V1u/SotUuNB3Fp8oB4C1fLBEhSlMcUJirz1E8\n" +
            "AziMCxS+VrRPDM+zfvpIJg3JljAh3PJHDiLu902v9w+Iplu1WyoB2aPfitxEhRN0\n" +
            "YwIDAQAB\n" +
            "-----END PUBLIC KEY-----";

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
        RequestProcessor processor = factory.forImplicitGrantHS(clientHelper, "clientSecret", "clientId", "domain", callback);
        assertThat(processor, is(notNullValue()));
        assertThat(processor.clientHelper, is(clientHelper));
        assertThat(processor.verifier, is(notNullValue()));
        assertThat(processor.callback, is(callback));
    }

    @Test
    public void shouldCreateForImplicitGrantRS() throws Exception {
        byte[] keyBytes = new PemReader(new StringReader(RS_CERT)).readPemObject().getContent();
        RequestProcessor processor = factory.forImplicitGrantRS(clientHelper, keyBytes, "clientId", "domain", callback);
        assertThat(processor, is(notNullValue()));
        assertThat(processor.clientHelper, is(clientHelper));
        assertThat(processor.verifier, is(notNullValue()));
        assertThat(processor.callback, is(callback));
    }

}