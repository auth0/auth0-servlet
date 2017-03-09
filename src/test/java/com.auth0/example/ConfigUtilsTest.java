package com.auth0.example;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;

import static org.hamcrest.CoreMatchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ConfigUtilsTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldThrowOnMissingValue() throws Exception {
        exception.expect(IllegalArgumentException.class);

        ServletConfig config = configureServlet(null, null);
        ConfigUtils.readRequiredParameter("key", config);
    }

    @Test
    public void shouldGetValueFromServletConfig() throws Exception {
        ServletConfig config = configureServlet("servlet", "context");
        String val = ConfigUtils.readRequiredParameter("key", config);
        Assert.assertThat(val, is("servlet"));
    }

    @Test
    public void shouldGetValueFromServletContext() throws Exception {
        ServletConfig config = configureServlet(null, "context");
        String val = ConfigUtils.readRequiredParameter("key", config);
        Assert.assertThat(val, is("context"));
    }

    @Test
    public void shouldGetEnabledFlagValue() throws Exception {
        ServletConfig config = mock(ServletConfig.class);
        when(config.getInitParameter("key")).thenReturn("true");

        boolean enabled = ConfigUtils.isFlagEnabled("key", config);
        Assert.assertThat(enabled, is(true));
    }

    @Test
    public void shouldGetDisabledFlagValue() throws Exception {
        ServletConfig config = mock(ServletConfig.class);
        when(config.getInitParameter("key")).thenReturn("false");

        boolean enabled = ConfigUtils.isFlagEnabled("key", config);
        Assert.assertThat(enabled, is(false));
    }

    @Test
    public void shouldGetDisabledFlagValueIfMissing() throws Exception {
        ServletConfig config = mock(ServletConfig.class);
        when(config.getInitParameter("key")).thenReturn(null);

        boolean enabled = ConfigUtils.isFlagEnabled("key", config);
        Assert.assertThat(enabled, is(false));
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