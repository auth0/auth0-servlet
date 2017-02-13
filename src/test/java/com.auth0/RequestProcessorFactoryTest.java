package com.auth0;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

public class RequestProcessorFactoryTest {

    private static final String RS_PUBLIC_KEY = "src/test/resources/public_key.pem";

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
        RequestProcessor processor = factory.forImplicitGrantRS(clientHelper, RS_PUBLIC_KEY, "clientId", "domain", callback);
        assertThat(processor, is(notNullValue()));
        assertThat(processor.clientHelper, is(clientHelper));
        assertThat(processor.verifier, is(notNullValue()));
        assertThat(processor.callback, is(callback));
    }

}