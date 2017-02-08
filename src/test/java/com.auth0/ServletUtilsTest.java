package com.auth0;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ServletUtilsTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldThrowOnMissingValue() throws Exception {
        exception.expect(IllegalArgumentException.class);

        ServletConfig config = configureServlet(null, null);
        ServletUtils.readRequiredParameter("key", config);
    }

    @Test
    public void shouldGetValueFromServletConfig() throws Exception {
        ServletConfig config = configureServlet("servlet", "context");
        String val = ServletUtils.readRequiredParameter("key", config);
        Assert.assertThat(val, is("servlet"));
    }

    @Test
    public void shouldGetValueFromServletContext() throws Exception {
        ServletConfig config = configureServlet(null, "context");
        String val = ServletUtils.readRequiredParameter("key", config);
        Assert.assertThat(val, is("context"));
    }


    @Test
    public void shouldGetEnabledFlagValue() throws Exception {
        ServletConfig config = mock(ServletConfig.class);
        when(config.getInitParameter("key")).thenReturn("true");

        boolean enabled = ServletUtils.isFlagEnabled("key", config);
        Assert.assertThat(enabled, is(true));
    }

    @Test
    public void shouldGetDisabledFlagValue() throws Exception {
        ServletConfig config = mock(ServletConfig.class);
        when(config.getInitParameter("key")).thenReturn("false");

        boolean enabled = ServletUtils.isFlagEnabled("key", config);
        Assert.assertThat(enabled, is(false));
    }

    @Test
    public void shouldGetDisabledFlagValueIfMissing() throws Exception {
        ServletConfig config = mock(ServletConfig.class);
        when(config.getInitParameter("key")).thenReturn(null);

        boolean enabled = ServletUtils.isFlagEnabled("key", config);
        Assert.assertThat(enabled, is(false));
    }

    @Test
    public void shouldGetRandomString() throws Exception {
        String string = ServletUtils.secureRandomString();
        Assert.assertThat(string, is(notNullValue()));
    }


    private ServletConfig configureServlet(String servletValue, String contextValue) {
        ServletContext context = mock(ServletContext.class);
        ServletConfig config = mock(ServletConfig.class);
        when(config.getServletContext()).thenReturn(context);
        when(context.getInitParameter("key")).thenReturn(contextValue);
        when(config.getInitParameter("key")).thenReturn(servletValue);
        return config;
    }
}