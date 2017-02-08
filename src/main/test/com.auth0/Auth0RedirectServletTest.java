package com.auth0;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.*;

public class Auth0RedirectServletTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    private Auth0RedirectServlet servlet;
    @Mock
    private AuthRequestProcessor authRequestProcessor;
    @Mock
    private HttpServletResponse res;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        Auth0RedirectServlet servlet = new Auth0RedirectServlet(authRequestProcessor);
        servlet.init(configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com"));
        this.servlet = spy(servlet);
    }

    @Test
    public void shouldThrowOnMissingClientIdConfig() throws Exception {
        exception.expect(IllegalArgumentException.class);

        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0Servlet(null, "secret", "domain");
        servlet.init(config);
    }

    @Test
    public void shouldThrowOnMissingClientSecretConfig() throws Exception {
        exception.expect(IllegalArgumentException.class);

        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0Servlet("id", null, "domain");
        servlet.init(config);
    }

    @Test
    public void shouldThrowOnMissingDomainConfig() throws Exception {
        exception.expect(IllegalArgumentException.class);

        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0Servlet("id", "secret", null);
        servlet.init(config);
    }

    @Test
    public void shouldThrowOnMissingClientIdContext() throws Exception {
        exception.expect(IllegalArgumentException.class);

        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0ServletContext(null, "secret", "domain");
        servlet.init(config);
    }

    @Test
    public void shouldThrowOnMissingClientSecretContext() throws Exception {
        exception.expect(IllegalArgumentException.class);

        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0ServletContext("id", null, "domain");
        servlet.init(config);
    }

    @Test
    public void shouldThrowOnMissingDomainContext() throws Exception {
        exception.expect(IllegalArgumentException.class);

        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0ServletContext("id", "secret", null);
        servlet.init(config);
    }

    @Test
    public void shouldCreateServletFromAuth0Config() throws Exception {
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "domain");
        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        servlet.init(config);
    }

    @Test
    public void shouldCreateServletFromAuth0Context() throws Exception {
        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0ServletContext("clientId", "clientSecret", "domain");
        servlet.init(config);
    }

    @Test
    public void shouldCreateRequestProcessor() throws Exception {
        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "domain");
        servlet.init(config);
        assertThat(servlet.getAuthRequestProcessor(), is(notNullValue()));
    }

    @Test
    public void shouldDestroyRequestProcessor() throws Exception {
        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "domain");
        servlet.init(config);
        servlet.destroy();
        assertThat(servlet.getAuthRequestProcessor(), is(nullValue()));
    }

    @Test
    public void shouldProcessRequestOnGET() throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        servlet.doGet(req, res);

        verify(authRequestProcessor).process(req, res);
    }

    @Test
    public void shouldProcessRequestOnPOST() throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        servlet.doPost(req, res);

        verify(authRequestProcessor).process(req, res);
    }

    @Test
    public void shouldRedirectOnFailure() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        Exception exc = mock(Exception.class);
        servlet.onFailure(req, res, exc);

        verify(res).sendRedirect("/login");
    }

    @Test
    public void shouldRedirectOnSuccess() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        Tokens tokens = mock(Tokens.class);
        servlet.onSuccess(req, res, tokens);

        verify(res).sendRedirect("/secure/home");
    }

    private ServletConfig configureAuth0Servlet(String clientId, String clientSecret, String domain) {
        ServletConfig config = mock(ServletConfig.class);
        when(config.getInitParameter("com.auth0.redirect_on_success")).thenReturn("/secure/home");
        when(config.getInitParameter("com.auth0.redirect_on_error")).thenReturn("/login");
        when(config.getInitParameter("com.auth0.client_id")).thenReturn(clientId);
        when(config.getInitParameter("com.auth0.client_secret")).thenReturn(clientSecret);
        when(config.getInitParameter("com.auth0.domain")).thenReturn(domain);

        ServletContext context = mock(ServletContext.class);
        when(config.getServletContext()).thenReturn(context);
        return config;
    }

    private ServletConfig configureAuth0ServletContext(String clientId, String clientSecret, String domain) {
        ServletContext context = mock(ServletContext.class);
        ServletConfig config = mock(ServletConfig.class);
        when(config.getServletContext()).thenReturn(context);
        when(config.getInitParameter("com.auth0.redirect_on_success")).thenReturn("/secure/home");
        when(config.getInitParameter("com.auth0.redirect_on_error")).thenReturn("/login");
        when(context.getInitParameter("com.auth0.client_id")).thenReturn(clientId);
        when(context.getInitParameter("com.auth0.client_secret")).thenReturn(clientSecret);
        when(context.getInitParameter("com.auth0.domain")).thenReturn(domain);
        return config;
    }
}