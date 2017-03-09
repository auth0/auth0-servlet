package com.auth0.lib;

import com.auth0.jwk.JwkProvider;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Collections;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.text.IsEmptyString.emptyOrNullString;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class Auth0MVCTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    @Mock
    private RequestProcessor requestProcessor;
    @Mock
    private RequestProcessorFactory requestProcessorFactory;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        when(requestProcessorFactory.forCodeGrant(eq("domain"), eq("clientId"), eq("clientSecret"), anyString())).thenReturn(requestProcessor);
        when(requestProcessorFactory.forImplicitGrant(eq("domain"), eq("clientId"), eq("clientSecret"), anyString())).thenReturn(requestProcessor);
        when(requestProcessorFactory.forImplicitGrant(eq("domain"), eq("clientId"), eq("clientSecret"), anyString(), any(JwkProvider.class))).thenReturn(requestProcessor);
    }

    @Test
    public void shouldThrowOnMissingDomainWhenCreatingHS256() throws Exception {
        exception.expect(NullPointerException.class);

        Auth0MVC.forHS256(null, "clientId", "clientSecret", "responseType");
    }

    @Test
    public void shouldThrowOnMissingClientIdWhenCreatingHS256() throws Exception {
        exception.expect(NullPointerException.class);

        Auth0MVC.forHS256("domain", null, "clientSecret", "responseType");
    }

    @Test
    public void shouldThrowOnMissingClientSecretWhenCreatingHS256() throws Exception {
        exception.expect(NullPointerException.class);

        Auth0MVC.forHS256("domain", "clientId", null, "responseType");
    }

    @Test
    public void shouldThrowOnMissingResponseTypeWhenCreatingHS256() throws Exception {
        exception.expect(NullPointerException.class);

        Auth0MVC.forHS256("domain", "clientId", null, "responseType");
    }

    @Test
    public void shouldThrowOnInvalidResponseTypeWhenCreatingHS256() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Response Type must contain either 'code' or 'token'.");

        Auth0MVC.forHS256("domain", "clientId", "clientSecret", "responseType");
    }

    @Test
    public void shouldThrowOnMissingDomainWhenCreatingRS256() throws Exception {
        exception.expect(NullPointerException.class);
        JwkProvider jwkProvider = mock(JwkProvider.class);

        Auth0MVC.forRS256(null, "clientId", "clientSecret", "responseType", jwkProvider);
    }

    @Test
    public void shouldThrowOnMissingClientIdWhenCreatingRS256() throws Exception {
        exception.expect(NullPointerException.class);
        JwkProvider jwkProvider = mock(JwkProvider.class);

        Auth0MVC.forRS256("domain", null, "clientSecret", "responseType", jwkProvider);
    }

    @Test
    public void shouldThrowOnMissingClientSecretWhenCreatingRS256() throws Exception {
        exception.expect(NullPointerException.class);
        JwkProvider jwkProvider = mock(JwkProvider.class);

        Auth0MVC.forRS256("domain", "clientId", null, "responseType", jwkProvider);
    }

    @Test
    public void shouldThrowOnMissingResponseTypeWhenCreatingRS256() throws Exception {
        exception.expect(NullPointerException.class);
        JwkProvider jwkProvider = mock(JwkProvider.class);

        Auth0MVC.forRS256("domain", "clientId", "clientSecret", null, jwkProvider);
    }

    @Test
    public void shouldThrowOnInvalidResponseTypeWhenCreatingRS256() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Response Type must contain either 'code' or 'token'.");
        JwkProvider jwkProvider = mock(JwkProvider.class);

        Auth0MVC.forRS256("domain", "clientId", "clientSecret", "responseType", jwkProvider);
    }

    @Test
    public void shouldCreateForHS256() throws Exception {
        Auth0MVC.forHS256("domain", "clientId", "clientSecret", "code");
    }

    @Test
    public void shouldCreateForRS256() throws Exception {
        JwkProvider jwkProvider = mock(JwkProvider.class);
        Auth0MVC.forRS256("domain", "clientId", "clientSecret", "token", jwkProvider);
    }

    @Test
    public void shouldProcessRequestWithCodeGrant() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forCodeGrant("domain", "clientId", "clientSecret", "code")).thenReturn(requestProcessor);

        Auth0MVC mvc = Auth0MVC.forHS256("domain", "clientId", "clientSecret", "code", requestProcessorFactory);
        HttpServletRequest req = new MockHttpServletRequest();
        mvc.handle(req);

        verify(requestProcessorFactory).forCodeGrant("domain", "clientId", "clientSecret", "code");
        verify(requestProcessor).process(req);
    }

    @Test
    public void shouldProcessRequestWithImplicitGrantRS() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        JwkProvider jwtProvider = mock(JwkProvider.class);
        when(requestProcessorFactory.forImplicitGrant("domain", "clientId", "clientSecret", "token", jwtProvider)).thenReturn(requestProcessor);

        Auth0MVC mvc = Auth0MVC.forRS256("domain", "clientId", "clientSecret", "token", jwtProvider, requestProcessorFactory);
        HttpServletRequest req = new MockHttpServletRequest();
        mvc.handle(req);

        verify(requestProcessorFactory).forImplicitGrant("domain", "clientId", "clientSecret", "token", jwtProvider);
        verify(requestProcessor).process(req);
    }

    @Test
    public void shouldProcessRequestWithImplicitGrantHS() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forImplicitGrant("domain", "clientId", "clientSecret", "token")).thenReturn(requestProcessor);

        Auth0MVC mvc = Auth0MVC.forHS256("domain", "clientId", "clientSecret", "token", requestProcessorFactory);
        HttpServletRequest req = new MockHttpServletRequest();
        mvc.handle(req);

        verify(requestProcessorFactory).forImplicitGrant("domain", "clientId", "clientSecret", "token");
        verify(requestProcessor).process(req);
    }

    @Test
    public void shouldThrowIfSecretCanNotBeParsedWithImplicitGrantHS() throws Exception {
        exception.expect(UnsupportedEncodingException.class);

        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forImplicitGrant("domain", "clientId", "clientSecret", "token")).thenThrow(UnsupportedEncodingException.class);
        Auth0MVC.forHS256("domain", "clientId", "clientSecret", "token", requestProcessorFactory);
    }

    @Test
    public void shouldBuildAuthorizeUriWithCustomStateAndNonce() throws Exception {
        Auth0MVC mvc = Auth0MVC.forHS256("domain", "clientId", "clientSecret", "token id_token", requestProcessorFactory);
        HttpServletRequest req = new MockHttpServletRequest();
        when(requestProcessor.getResponseType()).thenReturn(Arrays.asList("token", "id_token"));
        mvc.buildAuthorizeUrl(req, "https://redirect.uri/here", "state", "nonce");

        verify(requestProcessor).buildAuthorizeUrl("https://redirect.uri/here", "state", "nonce");
    }

    @Test
    public void shouldNotSaveNonceInSessionIfRequestTypeIsNotIdToken() throws Exception {
        Auth0MVC mvc = Auth0MVC.forHS256("domain", "clientId", "clientSecret", "token", requestProcessorFactory);
        HttpServletRequest req = new MockHttpServletRequest();
        when(requestProcessor.getResponseType()).thenReturn(Collections.singletonList("token"));
        mvc.buildAuthorizeUrl(req, "https://redirect.uri/here");

        ArgumentCaptor<String> stateCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> nonceCaptor = ArgumentCaptor.forClass(String.class);
        verify(requestProcessor).buildAuthorizeUrl(eq("https://redirect.uri/here"), stateCaptor.capture(), nonceCaptor.capture());

        assertThat(stateCaptor.getValue(), is(not(emptyOrNullString())));
        assertThat(nonceCaptor.getValue(), is(not(emptyOrNullString())));
        String savedState = (String) req.getSession(true).getAttribute("com.auth0.state");
        String savedNonce = (String) req.getSession(true).getAttribute("com.auth0.nonce");
        assertThat(savedState, is(stateCaptor.getValue()));
        assertThat(savedNonce, is(nullValue()));
    }

    @Test
    public void shouldSaveNonceInSessionIfRequestTypeIsIdToken() throws Exception {
        Auth0MVC mvc = Auth0MVC.forHS256("domain", "clientId", "clientSecret", "token id_token", requestProcessorFactory);
        HttpServletRequest req = new MockHttpServletRequest();
        when(requestProcessor.getResponseType()).thenReturn(Arrays.asList("token", "id_token"));
        mvc.buildAuthorizeUrl(req, "https://redirect.uri/here");

        ArgumentCaptor<String> stateCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> nonceCaptor = ArgumentCaptor.forClass(String.class);
        verify(requestProcessor).buildAuthorizeUrl(eq("https://redirect.uri/here"), stateCaptor.capture(), nonceCaptor.capture());

        assertThat(stateCaptor.getValue(), is(not(emptyOrNullString())));
        assertThat(nonceCaptor.getValue(), is(not(emptyOrNullString())));
        String savedState = (String) req.getSession(true).getAttribute("com.auth0.state");
        String savedNonce = (String) req.getSession(true).getAttribute("com.auth0.nonce");
        assertThat(savedState, is(stateCaptor.getValue()));
        assertThat(savedNonce, is(nonceCaptor.getValue()));
    }

}