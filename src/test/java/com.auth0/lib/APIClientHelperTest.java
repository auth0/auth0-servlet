package com.auth0.lib;

import com.auth0.client.auth.AuthAPI;
import com.auth0.json.auth.TokenHolder;
import com.auth0.json.auth.UserInfo;
import com.auth0.net.AuthRequest;
import com.auth0.net.Request;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Collections;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.*;

public class APIClientHelperTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    @Mock
    private AuthAPI client;
    private APIClientHelper helper;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        helper = new APIClientHelper(client);
    }

    @Test
    public void shouldThrowOnFetchUserIdWithoutToken() throws Exception {
        exception.expect(NullPointerException.class);
        helper.fetchUserId(null);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void shouldFetchUserId() throws Exception {
        UserInfo info = mock(UserInfo.class);
        Request<UserInfo> request = mock(Request.class);
        when(client.userInfo("theAccessToken")).thenReturn(request);
        when(request.execute()).thenReturn(info);
        when(info.getValues()).thenReturn(Collections.<String, Object>singletonMap("sub", "auth0|123asd"));

        String id = helper.fetchUserId("theAccessToken");
        verify(client).userInfo("theAccessToken");
        assertThat(id, is("auth0|123asd"));
    }

    @Test
    public void shouldThrowOnExchangeCodeForTokensWithoutCode() throws Exception {
        exception.expect(NullPointerException.class);
        helper.exchangeCodeForTokens(null, "https://me.auth0.com/callback");
    }

    @Test
    public void shouldThrowOnExchangeCodeForTokensWithoutRedirectUri() throws Exception {
        exception.expect(NullPointerException.class);
        helper.exchangeCodeForTokens("abc123", null);
    }

    @Test
    public void shouldExchangeCodeForTokens() throws Exception {
        TokenHolder holder = mock(TokenHolder.class);
        AuthRequest request = mock(AuthRequest.class);
        when(client.exchangeCode("abc123", "https://me.auth0.com/callback")).thenReturn(request);
        when(request.execute()).thenReturn(holder);
        when(holder.getAccessToken()).thenReturn("theAccessToken");
        when(holder.getIdToken()).thenReturn("theIdToken");
        when(holder.getRefreshToken()).thenReturn("theRefreshToken");
        when(holder.getTokenType()).thenReturn("theType");
        when(holder.getExpiresIn()).thenReturn(9999L);

        Tokens tokens = helper.exchangeCodeForTokens("abc123", "https://me.auth0.com/callback");
        verify(client).exchangeCode("abc123", "https://me.auth0.com/callback");
        assertThat(tokens, is(notNullValue()));
        assertThat(tokens.getAccessToken(), is("theAccessToken"));
        assertThat(tokens.getIdToken(), is("theIdToken"));
        assertThat(tokens.getRefreshToken(), is("theRefreshToken"));
        assertThat(tokens.getType(), is("theType"));
        assertThat(tokens.getExpiresIn(), is(9999L));
    }
}