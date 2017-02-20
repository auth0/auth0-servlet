package com.auth0.lib;

import com.auth0.exception.Auth0Exception;
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

public class RequestProcessorTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    @Mock
    private TokensCallback callback;
    @Mock
    private APIClientHelper clientHelper;
    @Mock
    private HttpServletResponse res;
    @Mock
    private TokenVerifier verifier;
    @Captor
    private ArgumentCaptor<Tokens> tokenCaptor;
    @Captor
    private ArgumentCaptor<Throwable> exceptionCaptor;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void shouldThrowOnMissingAPIClientHelper() throws Exception {
        exception.expect(NullPointerException.class);
        new RequestProcessor(null, null, callback);
    }

    @Test
    public void shouldNotThrowOnMissingTokenVerifier() throws Exception {
        new RequestProcessor(clientHelper, null, callback);
    }

    @Test
    public void shouldThrowOnMissingCallback() throws Exception {
        exception.expect(NullPointerException.class);
        new RequestProcessor(clientHelper, null, null);
    }

    @Test
    public void shouldCallOnFailureIfRequestHasError() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("error", "something happened");
        HttpServletRequest req = getRequest(params);

        RequestProcessor handler = new RequestProcessor(clientHelper, callback);
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

        RequestProcessor handler = new RequestProcessor(clientHelper, callback);
        handler.process(req, res);

        verify(callback).onFailure(eq(req), eq(res), exceptionCaptor.capture());
        assertThat(exceptionCaptor.getValue(), is(notNullValue()));
        assertThat(exceptionCaptor.getValue(), is(instanceOf(IllegalStateException.class)));
        assertThat(exceptionCaptor.getValue().getMessage(), is("Invalid state or error"));
    }

    //Implicit Grant

    @Test
    public void shouldThrowOnMissingCodeAndImplicitGrantNotAllowed() throws Exception {
        exception.expect(IllegalStateException.class);
        exception.expectMessage("Implicit Grant not allowed.");

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        ServletUtils.setSessionState(req, "1234");

        RequestProcessor handler = new RequestProcessor(clientHelper, callback);
        handler.process(req, res);
    }

    @Test
    public void shouldVerifyIdTokenOnImplicitGrant() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        ServletUtils.setSessionState(req, "1234");
        ServletUtils.setSessionNonce(req, "nnnccc");

        when(verifier.verifyNonce("theIdToken", "nnnccc")).thenReturn("auth0|user123");

        RequestProcessor handler = new RequestProcessor(clientHelper, verifier, callback);
        handler.process(req, res);

        verify(clientHelper, never()).fetchUserId(anyString());
        verify(callback).onSuccess(eq(req), eq(res), tokenCaptor.capture());
        assertThat(tokenCaptor.getValue().getAccessToken(), is("theAccessToken"));
        assertThat(tokenCaptor.getValue().getIdToken(), is("theIdToken"));
        assertThat(ServletUtils.getSessionUserId(req), is("auth0|user123"));
    }

    @Test
    public void shouldFailToVerifyIdTokenOnImplicitGrant() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        ServletUtils.setSessionState(req, "1234");

        when(verifier.verifyNonce("theIdToken", "nnnccc")).thenReturn(null);

        RequestProcessor handler = new RequestProcessor(clientHelper, verifier, callback);
        handler.process(req, res);

        verify(clientHelper, never()).fetchUserId(anyString());
        verify(callback).onFailure(eq(req), eq(res), exceptionCaptor.capture());
        assertThat(exceptionCaptor.getValue(), is(notNullValue()));
        assertThat(exceptionCaptor.getValue(), is(instanceOf(IllegalStateException.class)));
        assertThat(exceptionCaptor.getValue().getMessage(), is("Couldn't obtain the User Id."));
        assertThat(ServletUtils.getSessionUserId(req), is(nullValue()));
    }


    //Code Grant


    @Test
    public void shouldFetchUserIdUsingAccessTokenOnCodeGrant() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        ServletUtils.setSessionState(req, "1234");
        Tokens betterTokens = mock(Tokens.class);
        when(clientHelper.exchangeCodeForTokens("abc123", "https://me.auth0.com:80/callback")).thenReturn(betterTokens);
        when(clientHelper.fetchUserId("theAccessToken")).thenReturn("auth0|user123");

        RequestProcessor handler = new RequestProcessor(clientHelper, callback);
        handler.process(req, res);
        verify(clientHelper).exchangeCodeForTokens("abc123", "https://me.auth0.com:80/callback");
        verify(clientHelper).fetchUserId("theAccessToken");

        verify(callback).onSuccess(eq(req), eq(res), tokenCaptor.capture());
        assertThat(ServletUtils.getSessionUserId(req), is("auth0|user123"));
        assertThat(tokenCaptor.getValue().getAccessToken(), is("theAccessToken"));
        assertThat(tokenCaptor.getValue().getIdToken(), is("theIdToken"));
    }

    @Test
    public void shouldFetchUserIdUsingTheBestAccessTokenOnCodeGrant() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        ServletUtils.setSessionState(req, "1234");
        Tokens betterTokens = mock(Tokens.class);
        when(betterTokens.getAccessToken()).thenReturn("theBestAccessToken");
        when(clientHelper.exchangeCodeForTokens("abc123", "https://me.auth0.com:80/callback")).thenReturn(betterTokens);
        when(clientHelper.fetchUserId("theBestAccessToken")).thenReturn("auth0|user123");

        RequestProcessor handler = new RequestProcessor(clientHelper, callback);
        handler.process(req, res);
        verify(clientHelper).exchangeCodeForTokens("abc123", "https://me.auth0.com:80/callback");
        verify(clientHelper).fetchUserId("theBestAccessToken");

        verify(callback).onSuccess(eq(req), eq(res), tokenCaptor.capture());
        assertThat(ServletUtils.getSessionUserId(req), is("auth0|user123"));
        assertThat(tokenCaptor.getValue().getAccessToken(), is("theBestAccessToken"));
        assertThat(tokenCaptor.getValue().getIdToken(), is("theIdToken"));
    }


    @Test
    public void shouldThrowOnExchangeTheAuthorizationCodeOnCodeGrant() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        ServletUtils.setSessionState(req, "1234");
        when(clientHelper.exchangeCodeForTokens("abc123", "https://me.auth0.com:80/callback")).thenThrow(Auth0Exception.class);

        RequestProcessor handler = new RequestProcessor(clientHelper, callback);
        handler.process(req, res);
        verify(clientHelper).exchangeCodeForTokens("abc123", "https://me.auth0.com:80/callback");

        verify(callback).onFailure(eq(req), eq(res), exceptionCaptor.capture());
        assertThat(exceptionCaptor.getValue(), is(notNullValue()));
        assertThat(exceptionCaptor.getValue(), is(instanceOf(Auth0Exception.class)));
        assertThat(ServletUtils.getSessionUserId(req), is(nullValue()));
    }

    @Test
    public void shouldThrowOnFetchTheUserIdOnCodeGrant() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        ServletUtils.setSessionState(req, "1234");
        Tokens betterTokens = mock(Tokens.class);
        when(clientHelper.exchangeCodeForTokens("abc123", "https://me.auth0.com:80/callback")).thenReturn(betterTokens);
        when(clientHelper.fetchUserId("theAccessToken")).thenThrow(Auth0Exception.class);

        RequestProcessor handler = new RequestProcessor(clientHelper, callback);
        handler.process(req, res);
        verify(clientHelper).fetchUserId("theAccessToken");

        verify(callback).onFailure(eq(req), eq(res), exceptionCaptor.capture());
        assertThat(exceptionCaptor.getValue(), is(notNullValue()));
        assertThat(exceptionCaptor.getValue(), is(instanceOf(Auth0Exception.class)));
        assertThat(ServletUtils.getSessionUserId(req), is(nullValue()));
    }

    @Test
    public void shouldFailToGetTheUserIdOnCodeGrant() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        ServletUtils.setSessionState(req, "1234");
        Tokens betterTokens = mock(Tokens.class);
        when(clientHelper.exchangeCodeForTokens("abc123", "https://me.auth0.com:80/callback")).thenReturn(betterTokens);
        when(clientHelper.fetchUserId("theAccessToken")).thenReturn(null);

        RequestProcessor handler = new RequestProcessor(clientHelper, callback);
        handler.process(req, res);
        verify(clientHelper).fetchUserId("theAccessToken");

        verify(callback).onFailure(eq(req), eq(res), exceptionCaptor.capture());
        assertThat(exceptionCaptor.getValue(), is(notNullValue()));
        assertThat(exceptionCaptor.getValue(), is(instanceOf(IllegalStateException.class)));
        assertThat(exceptionCaptor.getValue().getMessage(), is("Couldn't obtain the User Id."));
        assertThat(ServletUtils.getSessionUserId(req), is(nullValue()));
    }


    // Utils

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