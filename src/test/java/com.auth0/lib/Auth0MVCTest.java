package com.auth0.lib;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class Auth0MVCTest {


    private static final String RS_CERT_PATH = "src/test/resources/certificate.pem";

    @Rule
    public ExpectedException exception = ExpectedException.none();
    @Mock
    private RequestProcessor requestProcessor;
    @Mock
    private RequestProcessorFactory requestProcessorFactory;
    @Mock
    private HttpServletResponse res;
    @Mock
    private TokensCallback callback;
    @Captor
    private ArgumentCaptor<Throwable> exceptionCaptor;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        when(requestProcessorFactory.forCodeGrant(any(APIClientHelper.class), any(TokensCallback.class))).thenReturn(requestProcessor);
        when(requestProcessorFactory.forImplicitGrantHS(any(APIClientHelper.class), anyString(), anyString(), anyString(), any(TokensCallback.class))).thenReturn(requestProcessor);
        when(requestProcessorFactory.forImplicitGrantRS(any(APIClientHelper.class), any(String.class), anyString(), anyString(), any(TokensCallback.class))).thenReturn(requestProcessor);
    }

    @Test
    public void shouldThrowOnMissingServletConfigClientId() throws Exception {
        exception.expect(IllegalArgumentException.class);

        ServletConfig config = configureAuth0Servlet(null, "secret", "domain", "/secure/home", "/login");
        new Auth0MVC(config, callback, requestProcessorFactory);
    }

    @Test
    public void shouldThrowOnMissingServletConfigClientSecret() throws Exception {
        exception.expect(IllegalArgumentException.class);

        ServletConfig config = configureAuth0Servlet("id", null, "domain", "/secure/home", "/login");
        new Auth0MVC(config, callback, requestProcessorFactory);
    }

    @Test
    public void shouldThrowOnMissingServletConfigDomain() throws Exception {
        exception.expect(IllegalArgumentException.class);

        ServletConfig config = configureAuth0Servlet("id", "secret", null, "/secure/home", "/login");
        new Auth0MVC(config, callback, requestProcessorFactory);
    }

    @Test
    public void shouldThrowOnMissingServletConfigRedirectOnSuccessURL() throws Exception {
        exception.expect(IllegalArgumentException.class);

        ServletConfig config = configureAuth0Servlet(null, "secret", "domain", null, "/login");
        new Auth0MVC(config, callback, requestProcessorFactory);
    }

    @Test
    public void shouldThrowOnMissingServletConfigRedirectOnErrorURL() throws Exception {
        exception.expect(IllegalArgumentException.class);

        ServletConfig config = configureAuth0Servlet(null, "secret", "domain", "/secure/home", null);
        new Auth0MVC(config, callback, requestProcessorFactory);
    }

    @Test
    public void shouldCreateServlet() throws Exception {
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "domain", "/secure/home", "/login");
        new Auth0MVC(config, callback, requestProcessorFactory);
    }

    @Test
    public void shouldProcessRequestOnGETWithCodeGrant() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forCodeGrant(any(APIClientHelper.class), any(TokensCallback.class))).thenReturn(requestProcessor);

        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com", "/secure/home", "/login");
        Auth0MVC servlets = new Auth0MVC(config, callback, requestProcessorFactory);

        HttpServletRequest req = new MockHttpServletRequest("GET", "");
        servlets.handle(req, res);

        verify(requestProcessorFactory).forCodeGrant(any(APIClientHelper.class), any(TokensCallback.class));
        verify(requestProcessor).process(req, res);
    }

    @Test
    public void shouldProcessRequestOnPOSTIfEnabledWithCodeGrant() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forCodeGrant(any(APIClientHelper.class), any(TokensCallback.class))).thenReturn(requestProcessor);
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "domain", "/secure/home", "/login");
        when(config.getInitParameter("com.auth0.allow_post")).thenReturn("true");
        Auth0MVC servlets = new Auth0MVC(config, callback, requestProcessorFactory);
        HttpServletRequest req = new MockHttpServletRequest("POST", "");
        servlets.handle(req, res);

        verify(requestProcessorFactory).forCodeGrant(any(APIClientHelper.class), any(TokensCallback.class));
        verify(requestProcessor).process(req, res);
        verify(callback, never()).onFailure(any(HttpServletRequest.class), any(HttpServletResponse.class), any(Throwable.class));
    }

    @Test
    public void shouldProcessRequestOnPOSTIfEnabledWithImplicitGrantRS() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forImplicitGrantRS(any(APIClientHelper.class), any(String.class), eq("me.auth0.com"), eq("clientId"), any(TokensCallback.class))).thenReturn(requestProcessor);

        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com", "/secure/home", "/login");
        when(config.getInitParameter("com.auth0.allow_post")).thenReturn("true");
        when(config.getInitParameter("com.auth0.use_implicit_grant")).thenReturn("true");
        when(config.getInitParameter("com.auth0.certificate")).thenReturn(RS_CERT_PATH);
        Auth0MVC servlets = new Auth0MVC(config, callback, requestProcessorFactory);
        HttpServletRequest req = new MockHttpServletRequest("POST", "");
        servlets.handle(req, res);

        verify(requestProcessorFactory).forImplicitGrantRS(any(APIClientHelper.class), any(String.class), eq("me.auth0.com"), eq("clientId"), any(TokensCallback.class));
        verify(requestProcessor).process(req, res);
        verify(callback, never()).onFailure(any(HttpServletRequest.class), any(HttpServletResponse.class), any(Throwable.class));
    }

    @Test
    public void shouldProcessRequestOnPOSTIfEnabledWithImplicitGrantHS() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forImplicitGrantHS(any(APIClientHelper.class), eq("clientSecret"), eq("me.auth0.com"), eq("clientId"), any(TokensCallback.class))).thenReturn(requestProcessor);

        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com", "/secure/home", "/login");
        when(config.getInitParameter("com.auth0.allow_post")).thenReturn("true");
        when(config.getInitParameter("com.auth0.use_implicit_grant")).thenReturn("true");
        Auth0MVC servlets = new Auth0MVC(config, callback, requestProcessorFactory);
        HttpServletRequest req = new MockHttpServletRequest("POST", "");
        servlets.handle(req, res);

        verify(requestProcessorFactory).forImplicitGrantHS(any(APIClientHelper.class), eq("clientSecret"), eq("me.auth0.com"), eq("clientId"), any(TokensCallback.class));
        verify(requestProcessor).process(req, res);
        verify(callback, never()).onFailure(any(HttpServletRequest.class), any(HttpServletResponse.class), any(Throwable.class));
    }

    @Test
    public void shouldThrowIfCertificateCanNotBeParsedWithImplicitGrantRS() throws Exception {
        exception.expect(IllegalStateException.class);
        exception.expectMessage("The PublicKey or Certificate for RS256 algorithm was invalid.");

        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forImplicitGrantRS(any(APIClientHelper.class), any(String.class), eq("me.auth0.com"), eq("clientId"), any(TokensCallback.class))).thenThrow(IOException.class);
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com", "/secure/home", "/login");
        when(config.getInitParameter("com.auth0.allow_post")).thenReturn("true");
        when(config.getInitParameter("com.auth0.use_implicit_grant")).thenReturn("true");
        when(config.getInitParameter("com.auth0.certificate")).thenReturn(RS_CERT_PATH);
        new Auth0MVC(config, callback, requestProcessorFactory);
    }

    @Test
    public void shouldThrowIfSecretCanNotBeParsedWithImplicitGrantHS() throws Exception {
        exception.expect(IllegalStateException.class);
        exception.expectMessage("Missing UTF-8 encoding support.");

        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forImplicitGrantHS(any(APIClientHelper.class), eq("clientSecret"), eq("me.auth0.com"), eq("clientId"), any(TokensCallback.class))).thenThrow(UnsupportedEncodingException.class);
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com", "/secure/home", "/login");
        when(config.getInitParameter("com.auth0.allow_post")).thenReturn("true");
        when(config.getInitParameter("com.auth0.use_implicit_grant")).thenReturn("true");
        new Auth0MVC(config, callback, requestProcessorFactory);
    }

    @Test
    public void shouldThrowIfImplicitGrantIsEnabledWithoutPOST() throws Exception {
        exception.expect(IllegalStateException.class);
        exception.expectMessage("Implicit Grant can only be used with a POST method. Enable the 'com.auth0.allow_post' parameter in the Servlet configuration and make sure to request the login with the 'response_mode=form_post' parameter.");

        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com", "/secure/home", "/login");
        when(config.getInitParameter("com.auth0.use_implicit_grant")).thenReturn("true");
        new Auth0MVC(config, callback, requestProcessorFactory);
    }

    @Test
    public void shouldRedirectOnGETIfImplicitGrantEnabled() throws Exception {
        HttpServletRequest req = new MockHttpServletRequest("GET", "");

        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "me.auth0.com", "/secure/home", "/login");
        when(config.getInitParameter("com.auth0.use_implicit_grant")).thenReturn("true");
        when(config.getInitParameter("com.auth0.allow_post")).thenReturn("true");
        Auth0MVC servlets = new Auth0MVC(config, callback, requestProcessorFactory);
        servlets.handle(req, res);

        verify(requestProcessor, never()).process(req, res);
        verify(callback).onFailure(eq(req), eq(res), exceptionCaptor.capture());

        Assert.assertThat(exceptionCaptor.getValue(), is(notNullValue()));
        Assert.assertThat(exceptionCaptor.getValue().getMessage(), is("Request with method GET not allowed."));
    }

    @Test
    public void shouldRedirectOnPOSTIfDisabled() throws Exception {
        ServletConfig config = configureAuth0Servlet("clientId", "secret", "domain", "/secure/home", "/login");
        Auth0MVC servlets = new Auth0MVC(config, callback, requestProcessorFactory);
        HttpServletRequest req = new MockHttpServletRequest("POST", "");
        servlets.handle(req, res);

        verify(requestProcessor, never()).process(req, res);
        verify(callback).onFailure(eq(req), eq(res), exceptionCaptor.capture());

        Assert.assertThat(exceptionCaptor.getValue(), is(notNullValue()));
        Assert.assertThat(exceptionCaptor.getValue().getMessage(), is("Request with method POST not allowed."));
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