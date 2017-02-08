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
        servlet.init(configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com", "/secure/home", "/login"));
        this.servlet = spy(servlet);
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
    public void shouldCreateRequestProcessor() throws Exception {
        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "domain", "/secure/home", "/login");
        servlet.init(config);
        assertThat(servlet.getAuthRequestProcessor(), is(notNullValue()));
    }

    @Test
    public void shouldDestroyRequestProcessor() throws Exception {
        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "domain", "/secure/home", "/login");
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

    private ServletConfig configureAuth0Servlet(String clientId, String clientSecret, String domain, String redirectOnSuccess, String redirectOnError) {
        ServletConfig config = mock(ServletConfig.class);
        when(config.getInitParameter("com.auth0.client_id")).thenReturn(clientId);
        when(config.getInitParameter("com.auth0.client_secret")).thenReturn(clientSecret);
        when(config.getInitParameter("com.auth0.domain")).thenReturn(domain);
        when(config.getInitParameter("com.auth0.redirect_on_success")).thenReturn(redirectOnSuccess);
        when(config.getInitParameter("com.auth0.redirect_on_error")).thenReturn(redirectOnError);

        ServletContext context = mock(ServletContext.class);
        when(config.getServletContext()).thenReturn(context);
        return config;
    }
}