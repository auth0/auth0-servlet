package com.auth0;

import com.auth0.lib.Auth0Servlets;
import com.auth0.lib.Tokens;
import com.auth0.lib.TokensCallback;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletResponse;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.*;

public class Auth0RedirectServletTest {

    private static final String RS_CERT_PATH = "src/test/resources/certificate.pem";

    @Rule
    public ExpectedException exception = ExpectedException.none();
    @Mock
    private HttpServletResponse res;
    @Mock
    private Auth0ServletsFactory factory;
    @Mock
    private Auth0Servlets auth0Servlets;
    private MockHttpServletRequest req;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        this.req = new MockHttpServletRequest();
        when(factory.newInstance(ArgumentMatchers.any(ServletConfig.class), ArgumentMatchers.any(TokensCallback.class))).thenReturn(auth0Servlets);
    }

    @Test
    public void shouldThrowOnMissingServletConfigClientId() throws Exception {
        exception.expect(IllegalArgumentException.class);

        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0Servlet(null, "secret", "domain", "/secure/home", "/login");
        servlet.init(config);
    }

    @Test
    public void shouldThrowOnMissingServletConfigClientSecret() throws Exception {
        exception.expect(IllegalArgumentException.class);

        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0Servlet("id", null, "domain", "/secure/home", "/login");
        servlet.init(config);
    }

    @Test
    public void shouldThrowOnMissingServletConfigDomain() throws Exception {
        exception.expect(IllegalArgumentException.class);

        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0Servlet("id", "secret", null, "/secure/home", "/login");
        servlet.init(config);
    }

    @Test
    public void shouldThrowOnMissingServletConfigRedirectOnSuccessURL() throws Exception {
        exception.expect(IllegalArgumentException.class);

        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0Servlet(null, "secret", "domain", null, "/login");
        servlet.init(config);
    }

    @Test
    public void shouldThrowOnMissingServletConfigRedirectOnErrorURL() throws Exception {
        exception.expect(IllegalArgumentException.class);

        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0Servlet(null, "secret", "domain", "/secure/home", null);
        servlet.init(config);
    }

    @Test
    public void shouldCreateServlet() throws Exception {
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "domain", "/secure/home", "/login");
        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        servlet.init(config);
    }

    @Test
    public void shouldCreateAuth0Servlets() throws Exception {
        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "domain", "/secure/home", "/login");
        servlet.init(config);
        assertThat(servlet.getAuth0Servlets(), is(notNullValue()));
    }

    @Test
    public void shouldDestroyAuth0Servlets() throws Exception {
        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "domain", "/secure/home", "/login");
        servlet.init(config);
        servlet.destroy();
        assertThat(servlet.getAuth0Servlets(), is(nullValue()));
    }

    @Test
    public void shouldProcessRequestOnGET() throws Exception {
        Auth0RedirectServlet servlet = new Auth0RedirectServlet(factory);
        servlet.init(configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com", "/secure/home", "/login"));
        servlet.doGet(req, res);

        verify(auth0Servlets).process(req, res);
    }

    @Test
    public void shouldProcessRequestOnPOST() throws Exception {
        Auth0RedirectServlet servlet = new Auth0RedirectServlet(factory);
        servlet.init(configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com", "/secure/home", "/login"));
        servlet.doPost(req, res);

        verify(auth0Servlets).process(req, res);
    }

    @Test
    public void shouldRedirectOnFailure() throws Exception {
        Exception exc = mock(Exception.class);
        Auth0RedirectServlet servlet = new Auth0RedirectServlet(factory);
        servlet.init(configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com", "/secure/home", "/login"));
        servlet.onFailure(req, res, exc);

        verify(res).sendRedirect("/login");
        verify(res, never()).sendError(anyInt());
    }

    @Test
    public void shouldRedirectOnSuccess() throws Exception {
        Tokens tokens = mock(Tokens.class);
        Auth0RedirectServlet servlet = new Auth0RedirectServlet(factory);
        servlet.init(configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com", "/secure/home", "/login"));
        servlet.onSuccess(req, res, tokens);

        verify(res).sendRedirect("/secure/home");
        verify(res, never()).sendError(anyInt());
    }

    private ServletConfig configureAuth0Servlet(String clientId, String clientSecret, String domain, String redirectOnSuccess, String redirectOnError) {
        ServletConfig config = mock(ServletConfig.class);
        when(config.getInitParameter("com.auth0.client_id")).thenReturn(clientId);
        when(config.getInitParameter("com.auth0.client_secret")).thenReturn(clientSecret);
        when(config.getInitParameter("com.auth0.domain")).thenReturn(domain);
        when(config.getInitParameter("com.auth0.redirect_on_success")).thenReturn(redirectOnSuccess);
        when(config.getInitParameter("com.auth0.redirect_on_error")).thenReturn(redirectOnError);

        ServletContext context = mock(ServletContext.class);
        when(context.getRealPath(RS_CERT_PATH)).thenReturn(RS_CERT_PATH);
        when(config.getServletContext()).thenReturn(context);
        return config;
    }
}