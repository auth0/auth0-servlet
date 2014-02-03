package com.auth0;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;

import org.junit.Test;

public class Auth0ServletCallbackTest {

    @Test
    public void readsParametersFromConfigOrContext() throws ServletException {
        final List<String> parameters = asList(
                "auth0.redirect_on_success",
                "auth0.redirect_on_error",
                "auth0.client_id",
                "auth0.client_secret",
                "auth0.domain");
        for(final String missing : parameters) {
            final List<String> defined = new ArrayList<>(parameters);
            defined.remove(missing);
            paramsDefinedInConfig(missing, defined);
            paramsDefinedInContext(missing, defined);
        }
    }

    private static void paramsDefinedInContext(final String missing, final List<String> defined)
            throws ServletException {
        final ServletConfig configWithoutParams = mock(ServletConfig.class);
        final ServletContext ctxWithParams = mock(ServletContext.class);
        for(final String parameter : defined) {
            when(ctxWithParams.getInitParameter(eq(parameter))).thenReturn("i-am-defined");
        }
        when(configWithoutParams.getServletContext()).thenReturn(ctxWithParams);
        init(missing, configWithoutParams);
    }

    private static void paramsDefinedInConfig(final String missing, final List<String> defined) throws ServletException {
        final ServletConfig configWithParams = mock(ServletConfig.class);
        for(final String parameter : defined) {
            when(configWithParams.getInitParameter(eq(parameter))).thenReturn("i-am-defined");
        }
        when(configWithParams.getServletContext()).thenReturn(mock(ServletContext.class));
        init(missing, configWithParams);
    }

    private static void init(final String missing, final ServletConfig config) throws ServletException {
        final Auth0ServletCallback cb = new Auth0ServletCallback();
        try {
            cb.init(config);
            fail("Expected init to fail on missing parameter: " + missing);
        }
        catch(final IllegalArgumentException e) {
            assertTrue("Expected failure to reference parameter: " + missing, e.getMessage().contains(missing));
        }
    }
}
