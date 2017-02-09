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
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class Auth0RedirectServletTest {

    private static final String RS_CERT = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuGbXWiK3dQTyCbX5xdE4\n" +
            "yCuYp0AF2d15Qq1JSXT/lx8CEcXb9RbDddl8jGDv+spi5qPa8qEHiK7FwV2KpRE9\n" +
            "83wGPnYsAm9BxLFb4YrLYcDFOIGULuk2FtrPS512Qea1bXASuvYXEpQNpGbnTGVs\n" +
            "WXI9C+yjHztqyL2h8P6mlThPY9E9ue2fCqdgixfTFIF9Dm4SLHbphUS2iw7w1JgT\n" +
            "69s7of9+I9l5lsJ9cozf1rxrXX4V1u/SotUuNB3Fp8oB4C1fLBEhSlMcUJirz1E8\n" +
            "AziMCxS+VrRPDM+zfvpIJg3JljAh3PJHDiLu902v9w+Iplu1WyoB2aPfitxEhRN0\n" +
            "YwIDAQAB\n" +
            "-----END PUBLIC KEY-----";

    @Rule
    public ExpectedException exception = ExpectedException.none();
    private Auth0RedirectServlet servlet;
    @Mock
    private RequestProcessor requestProcessor;
    @Mock
    private RequestProcessorFactory requestProcessorFactory;
    @Mock
    private HttpServletResponse res;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        when(requestProcessorFactory.forCodeGrant(any(APIClientHelper.class), any(TokensCallback.class))).thenReturn(requestProcessor);
        when(requestProcessorFactory.forImplicitGrantHS(any(APIClientHelper.class), anyString(), anyString(), anyString(), any(TokensCallback.class))).thenReturn(requestProcessor);
        when(requestProcessorFactory.forImplicitGrantRS(any(APIClientHelper.class), any(byte[].class), anyString(), anyString(), any(TokensCallback.class))).thenReturn(requestProcessor);
        Auth0RedirectServlet servlet = new Auth0RedirectServlet(requestProcessorFactory);
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
        assertThat(servlet.getRequestProcessor(), is(notNullValue()));
    }

    @Test
    public void shouldDestroyRequestProcessor() throws Exception {
        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "domain", "/secure/home", "/login");
        servlet.init(config);
        servlet.destroy();
        assertThat(servlet.getRequestProcessor(), is(nullValue()));
    }

    @Test
    public void shouldProcessRequestOnGETWithCodeGrant() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forCodeGrant(any(APIClientHelper.class), any(TokensCallback.class))).thenReturn(requestProcessor);
        Auth0RedirectServlet servlet = new Auth0RedirectServlet(requestProcessorFactory);
        servlet.init(configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com", "/secure/home", "/login"));
        servlet = spy(servlet);

        HttpServletRequest req = new MockHttpServletRequest();
        servlet.doGet(req, res);

        verify(requestProcessorFactory).forCodeGrant(any(APIClientHelper.class), any(TokensCallback.class));
        verify(requestProcessor).process(req, res);
    }

    @Test
    public void shouldProcessRequestOnPOSTIfEnabledWithCodeGrant() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forCodeGrant(any(APIClientHelper.class), any(TokensCallback.class))).thenReturn(requestProcessor);
        Auth0RedirectServlet servlet = new Auth0RedirectServlet(requestProcessorFactory);
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "domain", "/secure/home", "/login");
        when(config.getInitParameter("com.auth0.allow_post")).thenReturn("true");
        HttpServletRequest req = new MockHttpServletRequest();
        servlet.init(config);
        servlet.doPost(req, res);

        verify(requestProcessorFactory).forCodeGrant(any(APIClientHelper.class), any(TokensCallback.class));
        verify(requestProcessor).process(req, res);
        verify(res, never()).sendError(anyInt());
    }

    @Test
    public void shouldProcessRequestOnGETWithImplicitGrantRS() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forImplicitGrantRS(any(APIClientHelper.class), any(byte[].class), eq("clientId"), eq("me.auth0.com"), any(TokensCallback.class))).thenReturn(requestProcessor);
        Auth0RedirectServlet servlet = new Auth0RedirectServlet(requestProcessorFactory);
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com", "/secure/home", "/login");
        when(config.getInitParameter("com.auth0.allow_post")).thenReturn("true");
        when(config.getInitParameter("com.auth0.use_implicit_grant")).thenReturn("true");
        when(config.getInitParameter("com.auth0.certificate")).thenReturn(RS_CERT);
        HttpServletRequest req = new MockHttpServletRequest();
        servlet.init(config);
        servlet.doGet(req, res);

        verify(requestProcessorFactory).forImplicitGrantRS(any(APIClientHelper.class), any(byte[].class), eq("clientId"), eq("me.auth0.com"), any(TokensCallback.class));
        verify(requestProcessor).process(req, res);
    }

    @Test
    public void shouldProcessRequestOnPOSTIfEnabledWithImplicitGrantRS() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forImplicitGrantRS(any(APIClientHelper.class), any(byte[].class), eq("clientId"), eq("me.auth0.com"), any(TokensCallback.class))).thenReturn(requestProcessor);
        Auth0RedirectServlet servlet = new Auth0RedirectServlet(requestProcessorFactory);
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com", "/secure/home", "/login");
        when(config.getInitParameter("com.auth0.allow_post")).thenReturn("true");
        when(config.getInitParameter("com.auth0.use_implicit_grant")).thenReturn("true");
        when(config.getInitParameter("com.auth0.certificate")).thenReturn(RS_CERT);
        HttpServletRequest req = new MockHttpServletRequest();
        servlet.init(config);
        servlet.doPost(req, res);

        verify(requestProcessorFactory).forImplicitGrantRS(any(APIClientHelper.class), any(byte[].class), eq("clientId"), eq("me.auth0.com"), any(TokensCallback.class));
        verify(requestProcessor).process(req, res);
        verify(res, never()).sendError(anyInt());
    }

    @Test
    public void shouldProcessRequestOnGETWithImplicitGrantHS() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forImplicitGrantHS(any(APIClientHelper.class), eq("clientSecret"), eq("clientId"), eq("me.auth0.com"), any(TokensCallback.class))).thenReturn(requestProcessor);
        Auth0RedirectServlet servlet = new Auth0RedirectServlet(requestProcessorFactory);
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com", "/secure/home", "/login");
        when(config.getInitParameter("com.auth0.allow_post")).thenReturn("true");
        when(config.getInitParameter("com.auth0.use_implicit_grant")).thenReturn("true");
        HttpServletRequest req = new MockHttpServletRequest();
        servlet.init(config);
        servlet.doGet(req, res);

        verify(requestProcessorFactory).forImplicitGrantHS(any(APIClientHelper.class), eq("clientSecret"), eq("clientId"), eq("me.auth0.com"), any(TokensCallback.class));
        verify(requestProcessor).process(req, res);
    }

    @Test
    public void shouldProcessRequestOnPOSTIfEnabledWithImplicitGrantHS() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forImplicitGrantHS(any(APIClientHelper.class), eq("clientSecret"), eq("clientId"), eq("me.auth0.com"), any(TokensCallback.class))).thenReturn(requestProcessor);
        Auth0RedirectServlet servlet = new Auth0RedirectServlet(requestProcessorFactory);
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com", "/secure/home", "/login");
        when(config.getInitParameter("com.auth0.allow_post")).thenReturn("true");
        when(config.getInitParameter("com.auth0.use_implicit_grant")).thenReturn("true");
        HttpServletRequest req = new MockHttpServletRequest();
        servlet.init(config);
        servlet.doPost(req, res);

        verify(requestProcessorFactory).forImplicitGrantHS(any(APIClientHelper.class), eq("clientSecret"), eq("clientId"), eq("me.auth0.com"), any(TokensCallback.class));
        verify(requestProcessor).process(req, res);
        verify(res, never()).sendError(anyInt());
    }

    @Test
    public void shouldThrowIfCertificateCanNotBeParsedWithImplicitGrantRS() throws Exception {
        exception.expect(ServletException.class);
        exception.expectMessage("The PublicKey certificate for RS256 algorithm was invalid.");

        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forImplicitGrantRS(any(APIClientHelper.class), any(byte[].class), eq("clientId"), eq("me.auth0.com"), any(TokensCallback.class))).thenThrow(IOException.class);
        Auth0RedirectServlet servlet = new Auth0RedirectServlet(requestProcessorFactory);
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com", "/secure/home", "/login");
        when(config.getInitParameter("com.auth0.allow_post")).thenReturn("true");
        when(config.getInitParameter("com.auth0.use_implicit_grant")).thenReturn("true");
        when(config.getInitParameter("com.auth0.certificate")).thenReturn(RS_CERT);
        servlet.init(config);
    }

    @Test
    public void shouldThrowIfSecretCanNotBeParsedWithImplicitGrantHS() throws Exception {
        exception.expect(ServletException.class);
        exception.expectMessage("Missing UTF-8 encoding support.");

        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forImplicitGrantHS(any(APIClientHelper.class), eq("clientSecret"), eq("clientId"), eq("me.auth0.com"), any(TokensCallback.class))).thenThrow(UnsupportedEncodingException.class);
        Auth0RedirectServlet servlet = new Auth0RedirectServlet(requestProcessorFactory);
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com", "/secure/home", "/login");
        when(config.getInitParameter("com.auth0.allow_post")).thenReturn("true");
        when(config.getInitParameter("com.auth0.use_implicit_grant")).thenReturn("true");
        servlet.init(config);
    }

    @Test
    public void shouldRedirectOnPOSTIfDisabled() throws Exception {
        HttpServletRequest req = new MockHttpServletRequest();
        servlet.doPost(req, res);

        verify(requestProcessor, never()).process(req, res);
        verify(res).sendError(405);
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