package com.auth0;

import com.auth0.lib.Auth0Servlets;
import com.auth0.lib.TokensCallback;
import org.junit.Test;

import javax.servlet.ServletConfig;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class Auth0ServletsFactoryTest {

    @Test
    public void shouldCreateInstance() throws Exception {
        Auth0ServletsFactory factory = new Auth0ServletsFactory();
        TokensCallback callback = mock(TokensCallback.class);
        Auth0Servlets instance = factory.newInstance(getRequiredConfig(), callback);

        assertThat(instance, is(notNullValue()));
    }

    private ServletConfig getRequiredConfig() {
        ServletConfig config = mock(ServletConfig.class);
        when(config.getInitParameter("com.auth0.client_id")).thenReturn("clientId");
        when(config.getInitParameter("com.auth0.client_secret")).thenReturn("clientSecret");
        when(config.getInitParameter("com.auth0.domain")).thenReturn("domain");
        return config;
    }
}