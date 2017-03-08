package com.auth0.lib;

import com.auth0.client.auth.AuthAPI;
import com.auth0.jwk.JwkProvider;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

public class RequestProcessorFactoryTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Mock
    private AuthAPI client;
    private RequestProcessorFactory factory;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        factory = new RequestProcessorFactory();
    }

    @Test
    public void shouldCreateForCodeGrant() throws Exception {
        RequestProcessor processor = factory.forCodeGrant(client);
        assertThat(processor, is(notNullValue()));
        assertThat(processor.client, is(client));
        assertThat(processor.verifier, is(nullValue()));
    }

    @Test
    public void shouldCreateForImplicitGrantHS() throws Exception {
        RequestProcessor processor = factory.forImplicitGrantHS(client, "clientSecret", "domain", "clientId");
        assertThat(processor, is(notNullValue()));
        assertThat(processor.client, is(client));
        assertThat(processor.verifier, is(notNullValue()));
    }

    @Test
    public void shouldCreateForImplicitGrantRS() throws Exception {
        JwkProvider jwkProvider = mock(JwkProvider.class);
        RequestProcessor processor = factory.forImplicitGrantRS(client, jwkProvider, "domain", "clientId");
        assertThat(processor, is(notNullValue()));
        assertThat(processor.client, is(client));
        assertThat(processor.verifier, is(notNullValue()));
    }

}