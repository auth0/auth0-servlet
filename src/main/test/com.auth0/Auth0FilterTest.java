package com.auth0;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static org.mockito.Mockito.*;

public class Auth0FilterTest {


    private Auth0Filter filter;

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {
        FilterConfig config = mock(FilterConfig.class);
        when(config.getInitParameter("com.auth0.redirect_on_authentication_error")).thenReturn("/login");
        filter = new Auth0Filter();
        filter.init(config);
    }

    @After
    public void tearDown() throws Exception {
        filter.destroy();
    }

    @Test
    public void shouldThrowIfRedirectOnAuthenticationErrorUrlIsNull() throws Exception {
        exception.expect(NullPointerException.class);

        Auth0Filter filter = new Auth0Filter();
        FilterConfig config = mock(FilterConfig.class);
        filter.init(config);
    }

    @Test
    public void shouldRedirectOnReject() throws Exception {
        HttpServletResponse res = mock(HttpServletResponse.class);
        filter.onReject(res);
        verify(res).sendRedirect("/login");
    }

    @Test
    public void shouldCallNextFilterOnSuccess() throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse res = mock(HttpServletResponse.class);
        FilterChain next = mock(FilterChain.class);

        filter.onSuccess(req, res, next);
        verify(next).doFilter(req, res);
    }

    @Test
    public void shouldAllowAuthenticatedRequests() throws Exception {
        HttpServletRequest req = getAuthRequest(true);
        HttpServletResponse res = mock(HttpServletResponse.class);
        FilterChain next = mock(FilterChain.class);

        filter.doFilter(req, res, next);
        verify(res, never()).sendRedirect(anyString());
        verify(next).doFilter(req, res);
    }

    @Test
    public void shouldRejectNonAuthenticatedRequests() throws Exception {
        HttpServletRequest req = getAuthRequest(false);
        HttpServletResponse res = mock(HttpServletResponse.class);
        FilterChain next = mock(FilterChain.class);

        filter.doFilter(req, res, next);
        verify(res).sendRedirect("/login");
        verify(next, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
    }

    private HttpServletRequest getAuthRequest(boolean isUserAuthenticated) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute("auth0UserId")).thenReturn(isUserAuthenticated ? "accessToken" : null);
        when(req.getSession()).thenReturn(session);
        when(req.getSession(anyBoolean())).thenReturn(session);
        return req;
    }
}