package com.auth0.lib;

import com.auth0.exception.Auth0Exception;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.*;

public class RequestProcessorTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    @Mock
    private APIClientHelper clientHelper;
    @Mock
    private TokenVerifier verifier;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void shouldThrowOnMissingAPIClientHelper() throws Exception {
        exception.expect(NullPointerException.class);
        new RequestProcessor(null, null);
    }

    @Test
    public void shouldNotThrowOnMissingTokenVerifier() throws Exception {
        new RequestProcessor(clientHelper, null);
    }

    @Test
    public void shouldThrowIfRequestHasError() throws Exception {
        exception.expect(IllegalStateException.class);
        exception.expectMessage("Invalid state or error");

        Map<String, Object> params = new HashMap<>();
        params.put("error", "something happened");
        HttpServletRequest req = getRequest(params);

        RequestProcessor handler = new RequestProcessor(clientHelper);
        handler.process(req);
    }

    @Test
    public void shouldThrowIfRequestHasInvalidState() throws Exception {
        exception.expect(IllegalStateException.class);
        exception.expectMessage("Invalid state or error");

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        HttpServletRequest req = getRequest(params);
        SessionUtils.setSessionState(req, "9999");

        RequestProcessor handler = new RequestProcessor(clientHelper);
        handler.process(req);
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
        SessionUtils.setSessionState(req, "1234");

        RequestProcessor handler = new RequestProcessor(clientHelper);
        handler.process(req);
    }

    @Test
    public void shouldVerifyIdTokenOnImplicitGrant() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        SessionUtils.setSessionState(req, "1234");
        SessionUtils.setSessionNonce(req, "nnnccc");

        when(verifier.verifyNonce("theIdToken", "nnnccc")).thenReturn("auth0|user123");

        RequestProcessor handler = new RequestProcessor(clientHelper, verifier);
        Tokens tokens = handler.process(req);

        verify(clientHelper, never()).fetchUserId(anyString());
        assertThat(tokens, is(notNullValue()));
        assertThat(tokens.getAccessToken(), is("theAccessToken"));
        assertThat(tokens.getIdToken(), is("theIdToken"));
        assertThat(SessionUtils.getSessionUserId(req), is("auth0|user123"));
    }

    @Test
    public void shouldThrowOnFailToVerifyIdTokenOnImplicitGrant() throws Exception {
        exception.expect(IllegalStateException.class);
        exception.expectMessage("Couldn't obtain the User Id.");

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        SessionUtils.setSessionState(req, "1234");

        when(verifier.verifyNonce("theIdToken", "nnnccc")).thenReturn(null);

        RequestProcessor handler = new RequestProcessor(clientHelper, verifier);
        handler.process(req);

        verify(clientHelper, never()).fetchUserId(anyString());
        assertThat(SessionUtils.getSessionUserId(req), is(nullValue()));
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
        SessionUtils.setSessionState(req, "1234");
        Tokens betterTokens = mock(Tokens.class);
        when(clientHelper.exchangeCodeForTokens("abc123", "https://me.auth0.com:80/callback")).thenReturn(betterTokens);
        when(clientHelper.fetchUserId("theAccessToken")).thenReturn("auth0|user123");

        RequestProcessor handler = new RequestProcessor(clientHelper);
        Tokens tokens = handler.process(req);
        verify(clientHelper).exchangeCodeForTokens("abc123", "https://me.auth0.com:80/callback");
        verify(clientHelper).fetchUserId("theAccessToken");

        assertThat(SessionUtils.getSessionUserId(req), is("auth0|user123"));
        assertThat(tokens, is(notNullValue()));
        assertThat(tokens.getAccessToken(), is("theAccessToken"));
        assertThat(tokens.getIdToken(), is("theIdToken"));
    }

    @Test
    public void shouldFetchUserIdUsingTheBestAccessTokenOnCodeGrant() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        SessionUtils.setSessionState(req, "1234");
        Tokens betterTokens = mock(Tokens.class);
        when(betterTokens.getAccessToken()).thenReturn("theBestAccessToken");
        when(clientHelper.exchangeCodeForTokens("abc123", "https://me.auth0.com:80/callback")).thenReturn(betterTokens);
        when(clientHelper.fetchUserId("theBestAccessToken")).thenReturn("auth0|user123");

        RequestProcessor handler = new RequestProcessor(clientHelper);
        Tokens tokens = handler.process(req);
        verify(clientHelper).exchangeCodeForTokens("abc123", "https://me.auth0.com:80/callback");
        verify(clientHelper).fetchUserId("theBestAccessToken");

        assertThat(SessionUtils.getSessionUserId(req), is("auth0|user123"));
        assertThat(tokens, is(notNullValue()));
        assertThat(tokens.getAccessToken(), is("theBestAccessToken"));
        assertThat(tokens.getIdToken(), is("theIdToken"));
    }

    @Test
    public void shouldThrowOnExchangeTheAuthorizationCodeOnCodeGrant() throws Exception {
        exception.expect(IllegalStateException.class);
        exception.expectMessage("Couldn't exchange the code for tokens");

        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        SessionUtils.setSessionState(req, "1234");
        when(clientHelper.exchangeCodeForTokens("abc123", "https://me.auth0.com:80/callback")).thenThrow(Auth0Exception.class);

        RequestProcessor handler = new RequestProcessor(clientHelper);
        handler.process(req);
        verify(clientHelper).exchangeCodeForTokens("abc123", "https://me.auth0.com:80/callback");
        assertThat(SessionUtils.getSessionUserId(req), is(nullValue()));
    }

    @Test
    public void shouldThrowOnFetchTheUserIdOnCodeGrant() throws Exception {
        exception.expect(IllegalStateException.class);
        exception.expectMessage("Couldn't exchange the code for tokens");

        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        SessionUtils.setSessionState(req, "1234");
        Tokens betterTokens = mock(Tokens.class);
        when(clientHelper.exchangeCodeForTokens("abc123", "https://me.auth0.com:80/callback")).thenReturn(betterTokens);
        when(clientHelper.fetchUserId("theAccessToken")).thenThrow(Auth0Exception.class);

        RequestProcessor handler = new RequestProcessor(clientHelper);
        handler.process(req);
        verify(clientHelper).fetchUserId("theAccessToken");
        assertThat(SessionUtils.getSessionUserId(req), is(nullValue()));
    }

    @Test
    public void shouldFailToGetTheUserIdOnCodeGrant() throws Exception {
        exception.expect(IllegalStateException.class);
        exception.expectMessage("Couldn't obtain the User Id.");
        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        SessionUtils.setSessionState(req, "1234");
        Tokens betterTokens = mock(Tokens.class);
        when(clientHelper.exchangeCodeForTokens("abc123", "https://me.auth0.com:80/callback")).thenReturn(betterTokens);
        when(clientHelper.fetchUserId("theAccessToken")).thenReturn(null);

        RequestProcessor handler = new RequestProcessor(clientHelper);
        handler.process(req);
        verify(clientHelper).fetchUserId("theAccessToken");

        assertThat(SessionUtils.getSessionUserId(req), is(nullValue()));
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