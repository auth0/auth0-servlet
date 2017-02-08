package com.auth0;

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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.*;

public class Auth0RedirectServletTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    private Auth0RedirectServlet servlet;
    @Mock
    private APIClientHelper clientHelper;
    @Mock
    private HttpServletResponse res;
    @Captor
    private ArgumentCaptor<Tokens> tokenCaptor;
    @Captor
    private ArgumentCaptor<Exception> exceptionCaptor;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        Auth0RedirectServlet servlet = new Auth0RedirectServlet(clientHelper);
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
    public void shouldCreateClientHelper() throws Exception {
        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "domain");
        servlet.init(config);
        assertThat(servlet.getClientHelper(), is(notNullValue()));
    }

    @Test
    public void shouldDestroyClientHelper() throws Exception {
        Auth0RedirectServlet servlet = new Auth0RedirectServlet();
        ServletConfig config = configureAuth0Servlet("clientId", "clientSecret", "domain");
        servlet.init(config);
        servlet.destroy();
        assertThat(servlet.getClientHelper(), is(nullValue()));
    }

    @Test
    public void shouldCallOnFailureIfRequestHasError() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("error", "something happened");
        HttpServletRequest req = getRequest(params);

        servlet.doGet(req, res);

        verify(servlet).onFailure(eq(req), eq(res), exceptionCaptor.capture());
        assertThat(exceptionCaptor.getValue(), is(notNullValue()));
        assertThat(exceptionCaptor.getValue(), is(instanceOf(IllegalStateException.class)));
        assertThat(exceptionCaptor.getValue().getMessage(), is("Invalid state or error"));
    }

    @Test
    public void shouldRedirectOnFailure() throws Exception {
        HttpServletRequest req = getRequest(Collections.<String, Object>emptyMap());
        Exception exc = mock(Exception.class);
        servlet.onFailure(req, res, exc);

        verify(res).sendRedirect("/login");
    }

    @Test
    public void shouldRedirectOnSuccess() throws Exception {
        HttpServletRequest req = getRequest(Collections.<String, Object>emptyMap());
        servlet.onSuccess(req, res);

        verify(res).sendRedirect("/secure/home");
    }

    @Test
    public void shouldCallOnFailureIfRequestHasInvalidState() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        HttpServletRequest req = getRequest(params);
        SessionUtils.setState(req, "9999");

        servlet.doGet(req, res);

        verify(servlet).onFailure(eq(req), eq(res), exceptionCaptor.capture());
        assertThat(exceptionCaptor.getValue(), is(notNullValue()));
        assertThat(exceptionCaptor.getValue(), is(instanceOf(IllegalStateException.class)));
        assertThat(exceptionCaptor.getValue().getMessage(), is("Invalid state or error"));
    }

    @Test
    public void shouldFetchUserIdUsingAccessToken() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        params.put("refresh_token", "theRefreshToken");
        HttpServletRequest req = getRequest(params);
        SessionUtils.setState(req, "1234");

        servlet.doGet(req, res);
        verify(clientHelper).fetchUserId("theAccessToken");
    }

    @Test
    public void shouldCallOnFailureIfCantGetUserId() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        HttpServletRequest req = getRequest(params);
        SessionUtils.setState(req, "1234");

        when(clientHelper.fetchUserId("theAccessToken")).thenReturn(null);

        servlet.doGet(req, res);

        verify(servlet).onFailure(eq(req), eq(res), exceptionCaptor.capture());
        assertThat(exceptionCaptor.getValue(), is(notNullValue()));
        assertThat(exceptionCaptor.getValue(), is(instanceOf(IllegalStateException.class)));
        assertThat(exceptionCaptor.getValue().getMessage(), is("Couldn't obtain the User Id."));
    }

    @Test
    public void shouldCallOnSuccessWhenRedirectedWithImplicitGrant() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        params.put("refresh_token", "theRefreshToken");
        params.put("token_type", "theType");
        params.put("expires_in", "360000");
        HttpServletRequest req = getRequest(params);
        SessionUtils.setState(req, "1234");

        when(clientHelper.fetchUserId("theAccessToken")).thenReturn("auth0|user123");

        servlet.doGet(req, res);

        verify(servlet).onSuccess(req, res);
        verify(servlet).onAuth0TokensObtained(tokenCaptor.capture());
        assertThat(SessionUtils.getAuth0UserId(req), is("auth0|user123"));
        assertThat(tokenCaptor.getValue().getAccessToken(), is("theAccessToken"));
        assertThat(tokenCaptor.getValue().getIdToken(), is("theIdToken"));
        assertThat(tokenCaptor.getValue().getRefreshToken(), is("theRefreshToken"));
        assertThat(tokenCaptor.getValue().getType(), is("theType"));
        assertThat(tokenCaptor.getValue().getExpiresIn(), is(360000L));
    }

    @Test
    public void shouldCallOnSuccessWhenRedirectedWithCodeGrant() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        params.put("refresh_token", "theRefreshToken");
        params.put("token_type", "theType");
        params.put("expires_in", "360000");
        HttpServletRequest req = getRequest(params);
        SessionUtils.setState(req, "1234");

        Tokens codeTokens = mock(Tokens.class);
        when(codeTokens.getAccessToken()).thenReturn("betterAccessToken");
        when(codeTokens.getIdToken()).thenReturn("betterIdToken");
        when(codeTokens.getRefreshToken()).thenReturn("betterRefreshToken");
        when(codeTokens.getType()).thenReturn("betterType");
        when(codeTokens.getExpiresIn()).thenReturn(99999L);
        when(clientHelper.exchangeCodeForTokens("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeTokens);
        when(clientHelper.fetchUserId("betterAccessToken")).thenReturn("auth0|user123");

        servlet.doGet(req, res);

        verify(servlet).onSuccess(req, res);
        verify(servlet).onAuth0TokensObtained(tokenCaptor.capture());
        assertThat(SessionUtils.getAuth0UserId(req), is("auth0|user123"));
        assertThat(tokenCaptor.getValue().getAccessToken(), is("betterAccessToken"));
        assertThat(tokenCaptor.getValue().getIdToken(), is("betterIdToken"));
        assertThat(tokenCaptor.getValue().getRefreshToken(), is("betterRefreshToken"));
        assertThat(tokenCaptor.getValue().getType(), is("betterType"));
        assertThat(tokenCaptor.getValue().getExpiresIn(), is(99999L));
    }


    private HttpServletRequest getRequest(Map<String, Object> parameters) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("me.auth0.com");
        request.setServerPort(80);
        request.setRequestURI("/callback");
        request.setParameters(parameters);
        return request;
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