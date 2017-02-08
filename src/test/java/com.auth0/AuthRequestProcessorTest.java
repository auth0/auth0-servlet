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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.*;

public class AuthRequestProcessorTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    @Mock
    private TokensCallback callback;
    @Mock
    private APIClientHelper clientHelper;
    @Mock
    private HttpServletResponse res;
    @Captor
    private ArgumentCaptor<Tokens> tokenCaptor;
    @Captor
    private ArgumentCaptor<Throwable> exceptionCaptor;
    private AuthRequestProcessor handler;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        handler = new AuthRequestProcessor(clientHelper, callback);
    }

    @Test
    public void shouldThrowOnMissingAPIClientHelper() throws Exception {
        exception.expect(NullPointerException.class);
        new AuthRequestProcessor(null, callback);
    }

    @Test
    public void shouldThrowOnMissingCallback() throws Exception {
        exception.expect(NullPointerException.class);
        new AuthRequestProcessor(clientHelper, null);
    }

    @Test
    public void shouldCreateInstance() throws Exception {
        new AuthRequestProcessor(clientHelper, callback);
    }

    @Test
    public void shouldCallOnFailureIfRequestHasError() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("error", "something happened");
        HttpServletRequest req = getRequest(params);

        handler.process(req, res);

        verify(callback).onFailure(eq(req), eq(res), exceptionCaptor.capture());
        assertThat(exceptionCaptor.getValue(), is(notNullValue()));
        assertThat(exceptionCaptor.getValue(), is(instanceOf(IllegalStateException.class)));
        assertThat(exceptionCaptor.getValue().getMessage(), is("Invalid state or error"));
    }


    @Test
    public void shouldCallOnFailureIfRequestHasInvalidState() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        HttpServletRequest req = getRequest(params);
        ServletUtils.setSessionState(req, "9999");

        handler.process(req, res);

        verify(callback).onFailure(eq(req), eq(res), exceptionCaptor.capture());
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
        ServletUtils.setSessionState(req, "1234");

        handler.process(req, res);
        verify(clientHelper).fetchUserId("theAccessToken");
    }

    @Test
    public void shouldCallOnFailureIfCantGetUserId() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        HttpServletRequest req = getRequest(params);
        ServletUtils.setSessionState(req, "1234");

        when(clientHelper.fetchUserId("theAccessToken")).thenReturn(null);

        handler.process(req, res);

        verify(callback).onFailure(eq(req), eq(res), exceptionCaptor.capture());
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
        ServletUtils.setSessionState(req, "1234");

        when(clientHelper.fetchUserId("theAccessToken")).thenReturn("auth0|user123");

        handler.process(req, res);

        verify(callback).onSuccess(eq(req), eq(res), tokenCaptor.capture());
        assertThat(ServletUtils.getSessionUserId(req), is("auth0|user123"));
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
        ServletUtils.setSessionState(req, "1234");

        Tokens codeTokens = mock(Tokens.class);
        when(codeTokens.getAccessToken()).thenReturn("betterAccessToken");
        when(codeTokens.getIdToken()).thenReturn("betterIdToken");
        when(codeTokens.getRefreshToken()).thenReturn("betterRefreshToken");
        when(codeTokens.getType()).thenReturn("betterType");
        when(codeTokens.getExpiresIn()).thenReturn(99999L);
        when(clientHelper.exchangeCodeForTokens("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeTokens);
        when(clientHelper.fetchUserId("betterAccessToken")).thenReturn("auth0|user123");

        handler.process(req, res);

        verify(callback).onSuccess(eq(req), eq(res), tokenCaptor.capture());
        assertThat(ServletUtils.getSessionUserId(req), is("auth0|user123"));
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
}