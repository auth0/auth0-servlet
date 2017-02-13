package com.auth0;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ServletUtilsTest {

    private static final String RS_CERTIFICATE = "src/test/resources/certificate.pem";
    private static final String RS_PUBLIC_KEY = "src/test/resources/public_key.pem";

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

    @Test
    public void shouldGetUserId() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.getSession().setAttribute("com.auth0.userId", "theUserId");

        assertThat(ServletUtils.getSessionUserId(req), is("theUserId"));
    }

    @Test
    public void shouldGetNullUserIdIfMissing() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();

        assertThat(ServletUtils.getSessionUserId(req), is(nullValue()));
    }

    @Test
    public void shouldSetUserId() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();

        ServletUtils.setSessionUserId(req, "newUserId");
        assertThat((String) req.getSession().getAttribute("com.auth0.userId"), is("newUserId"));
    }

    @Test
    public void shouldSetState() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();

        ServletUtils.setSessionState(req, "123456");
        assertThat((String) req.getSession().getAttribute("com.auth0.state"), is("123456"));
    }

    @Test
    public void shouldAcceptBothNullStates() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        boolean validState = ServletUtils.checkSessionState(req, null);
        assertThat(validState, is(true));
    }

    @Test
    public void shouldCheckAndRemoveInvalidState() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.getSession().setAttribute("com.auth0.state", "123456");

        boolean validState = ServletUtils.checkSessionState(req, "abcdef");
        assertThat(validState, is(false));
        assertThat(req.getSession().getAttribute("com.auth0.state"), is(nullValue()));
    }

    @Test
    public void shouldCheckAndRemoveCorrectState() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.getSession().setAttribute("com.auth0.state", "123456");

        boolean validState = ServletUtils.checkSessionState(req, "123456");
        assertThat(validState, is(true));
        assertThat(req.getSession().getAttribute("com.auth0.state"), is(nullValue()));
    }

    @Test
    public void shouldSetNonce() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();

        ServletUtils.setSessionNonce(req, "123456");
        assertThat((String) req.getSession().getAttribute("com.auth0.nonce"), is("123456"));
    }

    @Test
    public void shouldGetAndRemoveNonce() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.getSession().setAttribute("com.auth0.nonce", "123456");

        String nonce = ServletUtils.removeSessionNonce(req);
        assertThat(nonce, is("123456"));
        assertThat(req.getSession().getAttribute("com.auth0.nonce"), is(nullValue()));
    }

    @Test
    public void shouldGetAndRemoveNonceIfMissing() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();

        String nonce = ServletUtils.removeSessionNonce(req);
        assertThat(nonce, is(nullValue()));
        assertThat(req.getSession().getAttribute("com.auth0.nonce"), is(nullValue()));
    }

    @Test
    public void shouldThrowOnReadRSAKeyWithNullPath() throws Exception {
        exception.expect(NullPointerException.class);
        ServletUtils.readPublicKeyFromFile(null);
    }

    @Test
    public void shouldThrowOnReadRSAKeyFromMissingFile() throws Exception {
        exception.expect(IOException.class);
        exception.expectMessage("Couldn't parse the RSA Public Key / Certificate file.");
        ServletUtils.readPublicKeyFromFile("/not/existing/file");
    }

    @Test
    public void shouldReadRSAKeyFromPublicKeyFile() throws Exception {
        RSAPublicKey key = ServletUtils.readPublicKeyFromFile(RS_PUBLIC_KEY);
        assertThat(key, is(notNullValue()));
    }

    @Test
    public void shouldReadRSAKeyFromCertificateFile() throws Exception {
        RSAPublicKey key = ServletUtils.readPublicKeyFromFile(RS_CERTIFICATE);
        assertThat(key, is(notNullValue()));
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