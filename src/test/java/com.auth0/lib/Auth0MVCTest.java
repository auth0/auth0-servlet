package com.auth0.lib;

import com.auth0.client.auth.AuthAPI;
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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.text.IsEmptyString.emptyOrNullString;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
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
        when(requestProcessorFactory.forCodeGrant(any(AuthAPI.class))).thenReturn(requestProcessor);
        when(requestProcessorFactory.forImplicitGrantHS(any(AuthAPI.class), anyString(), anyString(), anyString())).thenReturn(requestProcessor);
        when(requestProcessorFactory.forImplicitGrantRS(any(AuthAPI.class), any(JwkProvider.class), anyString(), anyString())).thenReturn(requestProcessor);
    }

    @Test
    public void shouldThrowOnMissingDomainWhenCreatingCode() throws Exception {
        exception.expect(NullPointerException.class);

        Auth0MVC.forCodeGrant(null, "clientId", "clientSecret");
    }

    @Test
    public void shouldThrowOnMissingClientIdWhenCreatingCode() throws Exception {
        exception.expect(NullPointerException.class);

        Auth0MVC.forCodeGrant("domain", null, "clientSecret");
    }

    @Test
    public void shouldThrowOnMissingClientSecretWhenCreatingCode() throws Exception {
        exception.expect(NullPointerException.class);

        Auth0MVC.forCodeGrant("domain", "clientId", null);
    }

    @Test
    public void shouldThrowOnMissingDomainWhenCreatingHS() throws Exception {
        exception.expect(NullPointerException.class);

        Auth0MVC.forImplicitGrant(null, "clientId", "clientSecret");
    }

    @Test
    public void shouldThrowOnMissingClientIdWhenCreatingHS() throws Exception {
        exception.expect(NullPointerException.class);

        Auth0MVC.forImplicitGrant("domain", null, "clientSecret");
    }

    @SuppressWarnings("ConstantConditions")
    @Test
    public void shouldThrowOnMissingClientSecretWhenCreatingHS() throws Exception {
        exception.expect(NullPointerException.class);

        String secret = null;
        Auth0MVC.forImplicitGrant("domain", "clientId", secret);
    }

    @Test
    public void shouldThrowOnMissingDomainWhenCreatingRS() throws Exception {
        exception.expect(NullPointerException.class);

        JwkProvider jwkProvider = mock(JwkProvider.class);
        Auth0MVC.forImplicitGrant(null, "clientId", jwkProvider);
    }

    @Test
    public void shouldThrowOnMissingClientIdWhenCreatingRS() throws Exception {
        exception.expect(NullPointerException.class);

        JwkProvider jwkProvider = mock(JwkProvider.class);
        Auth0MVC.forImplicitGrant("domain", null, jwkProvider);
    }

    @SuppressWarnings("ConstantConditions")
    @Test
    public void shouldThrowOnMissingJwtProviderWhenCreatingRS() throws Exception {
        exception.expect(NullPointerException.class);

        JwkProvider jwkProvider = null;
        Auth0MVC.forImplicitGrant("domain", "clientId", jwkProvider);
    }

    @Test
    public void shouldCreateForCode() throws Exception {
        Auth0MVC.forCodeGrant("domain", "clientId", "clientSecret");
    }

    @Test
    public void shouldCreateForHS() throws Exception {
        Auth0MVC.forImplicitGrant("domain", "clientId", "clientSecret");
    }

    @Test
    public void shouldCreateForRS() throws Exception {
        Auth0MVC.forImplicitGrant("domain", "clientId", mock(JwkProvider.class));
    }

    @Test
    public void shouldProcessRequestWithCodeGrant() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forCodeGrant(any(AuthAPI.class))).thenReturn(requestProcessor);

        Auth0MVC mvc = Auth0MVC.forCodeGrant("domain", "clientId", "clientSecret", requestProcessorFactory);
        HttpServletRequest req = new MockHttpServletRequest();
        mvc.handle(req);

        verify(requestProcessorFactory).forCodeGrant(any(AuthAPI.class));
        verify(requestProcessor).process(req);
    }

    @Test
    public void shouldProcessRequestWithImplicitGrantRS() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        JwkProvider jwtProvider = mock(JwkProvider.class);
        when(requestProcessorFactory.forImplicitGrantRS(any(AuthAPI.class), eq(jwtProvider), eq("me.auth0.com"), eq("clientId"))).thenReturn(requestProcessor);

        Auth0MVC mvc = Auth0MVC.forImplicitGrant("me.auth0.com", "clientId", jwtProvider, requestProcessorFactory);
        HttpServletRequest req = new MockHttpServletRequest();
        mvc.handle(req);

        verify(requestProcessorFactory).forImplicitGrantRS(any(AuthAPI.class), eq(jwtProvider), eq("me.auth0.com"), eq("clientId"));
        verify(requestProcessor).process(req);
    }

    @Test
    public void shouldProcessRequestWithImplicitGrantHS() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forImplicitGrantHS(any(AuthAPI.class), eq("clientSecret"), eq("me.auth0.com"), eq("clientId"))).thenReturn(requestProcessor);

        Auth0MVC mvc = Auth0MVC.forImplicitGrant("me.auth0.com", "clientId", "clientSecret", requestProcessorFactory);
        HttpServletRequest req = new MockHttpServletRequest();
        mvc.handle(req);

        verify(requestProcessorFactory).forImplicitGrantHS(any(AuthAPI.class), eq("clientSecret"), eq("me.auth0.com"), eq("clientId"));
        verify(requestProcessor).process(req);
    }

    @Test
    public void shouldThrowIfSecretCanNotBeParsedWithImplicitGrantHS() throws Exception {
        exception.expect(UnsupportedEncodingException.class);

        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forImplicitGrantHS(any(AuthAPI.class), eq("clientSecret"), eq("me.auth0.com"), eq("clientId"))).thenThrow(UnsupportedEncodingException.class);
        Auth0MVC.forImplicitGrant("me.auth0.com", "clientId", "clientSecret", requestProcessorFactory);
    }

    @Test
    public void shouldBuildAuthorizeUriWithCustomStateAndNonce() throws Exception {
        Auth0MVC mvc = Auth0MVC.forCodeGrant("domain", "clientId", "clientSecret", requestProcessorFactory);
        HttpServletRequest req = new MockHttpServletRequest();
        mvc.buildAuthorizeUrl(req, "https://redirect.uri/here", "responseType", "state", "nonce");

        verify(requestProcessor).buildAuthorizeUrl("https://redirect.uri/here", "responseType", "state", "nonce");
    }

    @Test
    public void shouldNotSaveNonceInSessionIfRequestTypeIsNotIdToken() throws Exception {
        Auth0MVC mvc = Auth0MVC.forCodeGrant("domain", "clientId", "clientSecret", requestProcessorFactory);
        HttpServletRequest req = new MockHttpServletRequest();
        mvc.buildAuthorizeUrl(req, "https://redirect.uri/here", "responseType");

        ArgumentCaptor<String> stateCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> nonceCaptor = ArgumentCaptor.forClass(String.class);
        verify(requestProcessor).buildAuthorizeUrl(eq("https://redirect.uri/here"), eq("responseType"), stateCaptor.capture(), nonceCaptor.capture());

        assertThat(stateCaptor.getValue(), is(not(emptyOrNullString())));
        assertThat(nonceCaptor.getValue(), is(not(emptyOrNullString())));
        String savedState = (String) req.getSession(true).getAttribute("com.auth0.state");
        String savedNonce = (String) req.getSession(true).getAttribute("com.auth0.nonce");
        assertThat(savedState, is(stateCaptor.getValue()));
        assertThat(savedNonce, is(nullValue()));
    }

    @Test
    public void shouldSaveNonceInSessionIfRequestTypeIsIdToken() throws Exception {
        Auth0MVC mvc = Auth0MVC.forCodeGrant("domain", "clientId", "clientSecret", requestProcessorFactory);
        HttpServletRequest req = new MockHttpServletRequest();
        mvc.buildAuthorizeUrl(req, "https://redirect.uri/here", "id_token");

        ArgumentCaptor<String> stateCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> nonceCaptor = ArgumentCaptor.forClass(String.class);
        verify(requestProcessor).buildAuthorizeUrl(eq("https://redirect.uri/here"), eq("id_token"), stateCaptor.capture(), nonceCaptor.capture());

        assertThat(stateCaptor.getValue(), is(not(emptyOrNullString())));
        assertThat(nonceCaptor.getValue(), is(not(emptyOrNullString())));
        String savedState = (String) req.getSession(true).getAttribute("com.auth0.state");
        String savedNonce = (String) req.getSession(true).getAttribute("com.auth0.nonce");
        assertThat(savedState, is(stateCaptor.getValue()));
        assertThat(savedNonce, is(nonceCaptor.getValue()));
    }

}