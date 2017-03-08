package com.auth0.lib;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.json.auth.UserInfo;
import com.auth0.net.AuthRequest;
import com.auth0.net.Request;
import org.hamcrest.CoreMatchers;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.*;

public class RequestProcessorTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    @Mock
    private AuthAPI client;
    @Mock
    private TokenVerifier verifier;
    @Mock
    private Request<UserInfo> userInfoRequest;
    @Mock
    private UserInfo userInfo;
    @Mock
    private AuthRequest codeExchangeRequest;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        when(userInfoRequest.execute()).thenReturn(userInfo);
        when(userInfo.getValues()).thenReturn(Collections.<String, Object>singletonMap("sub", "auth0|user123"));
        TokenHolder holder = mock(TokenHolder.class);
        when(codeExchangeRequest.execute()).thenReturn(holder);
    }

    @Test
    public void shouldThrowOnMissingAPIClientHelper() throws Exception {
        exception.expect(NullPointerException.class);
        new RequestProcessor(null, null);
    }

    @Test
    public void shouldNotThrowOnMissingTokenVerifier() throws Exception {
        new RequestProcessor(client, null);
    }

    @Test
    public void shouldThrowIfRequestHasError() throws Exception {
        exception.expect(ProcessorException.class);
        exception.expectMessage("The request contains an error: something happened");

        Map<String, Object> params = new HashMap<>();
        params.put("error", "something happened");
        HttpServletRequest req = getRequest(params);

        RequestProcessor handler = new RequestProcessor(client);
        handler.process(req);
    }

    @Test
    public void shouldThrowIfRequestHasInvalidState() throws Exception {
        exception.expect(ProcessorException.class);
        exception.expectMessage("The request contains an invalid state");

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        HttpServletRequest req = getRequest(params);
        SessionUtils.setSessionState(req, "9999");

        RequestProcessor handler = new RequestProcessor(client);
        handler.process(req);
    }

    //Implicit Grant

    @Test
    public void shouldThrowOnMissingCodeAndImplicitGrantNotAllowed() throws Exception {
        exception.expect(ProcessorException.class);
        exception.expectMessage("Implicit Grant not allowed.");

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        SessionUtils.setSessionState(req, "1234");

        RequestProcessor handler = new RequestProcessor(client);
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

        RequestProcessor handler = new RequestProcessor(client, verifier);
        Tokens tokens = handler.process(req);

        verify(client, never()).userInfo(anyString());
        assertThat(tokens, is(notNullValue()));
        assertThat(tokens.getAccessToken(), is("theAccessToken"));
        assertThat(tokens.getIdToken(), is("theIdToken"));
        assertThat(SessionUtils.getSessionUserId(req), is("auth0|user123"));
    }

    @Test
    public void shouldThrowOnFailToVerifyIdTokenOnImplicitGrant() throws Exception {
        exception.expect(ProcessorException.class);
        exception.expectMessage("Couldn't obtain the User Id.");

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        SessionUtils.setSessionState(req, "1234");

        when(verifier.verifyNonce("theIdToken", "nnnccc")).thenReturn(null);

        RequestProcessor handler = new RequestProcessor(client, verifier);
        handler.process(req);

        verify(client, never()).userInfo(anyString());
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
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);
        when(client.userInfo("theAccessToken")).thenReturn(userInfoRequest);

        RequestProcessor handler = new RequestProcessor(client);
        Tokens tokens = handler.process(req);
        verify(client).exchangeCode("abc123", "https://me.auth0.com:80/callback");
        verify(client).userInfo("theAccessToken");

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
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);
        TokenHolder holder = mock(TokenHolder.class);
        when(holder.getAccessToken()).thenReturn("theBestAccessToken");
        when(codeExchangeRequest.execute()).thenReturn(holder);
        when(client.userInfo("theBestAccessToken")).thenReturn(userInfoRequest);

        RequestProcessor handler = new RequestProcessor(client);
        Tokens tokens = handler.process(req);
        verify(client).exchangeCode("abc123", "https://me.auth0.com:80/callback");
        verify(client).userInfo("theBestAccessToken");

        assertThat(SessionUtils.getSessionUserId(req), is("auth0|user123"));
        assertThat(tokens, is(notNullValue()));
        assertThat(tokens.getAccessToken(), is("theBestAccessToken"));
        assertThat(tokens.getIdToken(), is("theIdToken"));
    }

    @Test
    public void shouldThrowOnExchangeTheAuthorizationCodeOnCodeGrant() throws Exception {
        exception.expect(ProcessorException.class);
        exception.expectMessage("Couldn't exchange the Authorization Code for Auth0 Tokens");

        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        SessionUtils.setSessionState(req, "1234");
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenThrow(Auth0Exception.class);

        RequestProcessor handler = new RequestProcessor(client);
        handler.process(req);
        verify(client).exchangeCode("abc123", "https://me.auth0.com:80/callback");
        assertThat(SessionUtils.getSessionUserId(req), is(nullValue()));
    }

    @Test
    public void shouldThrowOnFetchTheUserIdOnCodeGrant() throws Exception {
        exception.expect(ProcessorException.class);
        exception.expectMessage("Couldn't exchange the Authorization Code for Auth0 Tokens");

        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        SessionUtils.setSessionState(req, "1234");

        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);
        when(client.userInfo("theAccessToken")).thenThrow(Auth0Exception.class);

        RequestProcessor handler = new RequestProcessor(client);
        handler.process(req);
        verify(client).userInfo("theAccessToken");
        assertThat(SessionUtils.getSessionUserId(req), is(nullValue()));
    }

    @Test
    public void shouldFailToGetTheUserIdOnCodeGrant() throws Exception {
        exception.expect(ProcessorException.class);
        exception.expectMessage("Couldn't obtain the User Id.");
        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        SessionUtils.setSessionState(req, "1234");
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);
        when(userInfo.getValues()).thenReturn(Collections.<String, Object>emptyMap());
        when(client.userInfo("theAccessToken")).thenReturn(userInfoRequest);

        RequestProcessor handler = new RequestProcessor(client);
        handler.process(req);
        verify(client).userInfo("theAccessToken");

        assertThat(SessionUtils.getSessionUserId(req), is(nullValue()));
    }

    @Test
    public void shouldBuildAuthorizeUrl() throws Exception {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
        RequestProcessor handler = new RequestProcessor(client);
        String authorizeUrl = handler.buildAuthorizeUrl("https://redirect.uri/here", "responseType", "state", "nonce");

        assertThat(authorizeUrl, is(notNullValue()));
        assertThat(authorizeUrl, CoreMatchers.startsWith("https://me.auth0.com/authorize?"));
        assertThat(authorizeUrl, containsString("client_id=clientId"));
        assertThat(authorizeUrl, containsString("redirect_uri=https://redirect.uri/here"));
        assertThat(authorizeUrl, containsString("response_type=responseType"));
        assertThat(authorizeUrl, containsString("state=state"));
        assertThat(authorizeUrl, not(containsString("nonce=nonce")));
    }

    @Test
    public void shouldBuildAuthorizeUrlWithNonceIfResponseTypeIsIdToken() throws Exception {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
        RequestProcessor handler = new RequestProcessor(client);
        String authorizeUrl = handler.buildAuthorizeUrl("https://redirect.uri/here", "id_token", "state", "nonce");

        assertThat(authorizeUrl, is(notNullValue()));
        assertThat(authorizeUrl, CoreMatchers.startsWith("https://me.auth0.com/authorize?"));
        assertThat(authorizeUrl, containsString("client_id=clientId"));
        assertThat(authorizeUrl, containsString("redirect_uri=https://redirect.uri/here"));
        assertThat(authorizeUrl, containsString("response_type=id_token"));
        assertThat(authorizeUrl, containsString("state=state"));
        assertThat(authorizeUrl, containsString("nonce=nonce"));
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