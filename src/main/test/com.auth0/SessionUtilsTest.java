package com.auth0;

import org.junit.Before;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.*;

public class SessionUtilsTest {

    private HttpServletRequest req;
    private HttpSession session;

    @Before
    public void setUp() throws Exception {
        req = mock(HttpServletRequest.class);
        session = mock(HttpSession.class);
        when(req.getSession()).thenReturn(session);
        when(req.getSession(anyBoolean())).thenReturn(session);
    }

    @Test
    public void shouldGetAuth0UserIdIfPresent() throws Exception {
        when(session.getAttribute("auth0UserId")).thenReturn("accessToken");
        assertThat(SessionUtils.getAuth0UserId(req), is("accessToken"));
    }

    @Test
    public void shouldGetNullAuth0UserIdIfMissing() throws Exception {
        assertThat(SessionUtils.getAuth0UserId(req), is(nullValue()));
    }

    @Test
    public void shouldSetAuth0UserId() throws Exception {
        SessionUtils.setAuth0UserId(req, "newUserId");
        verify(session).setAttribute("auth0UserId", "newUserId");
    }

    @Test
    public void shouldGetStateIfPresent() throws Exception {
        when(session.getAttribute("state")).thenReturn("1234567890");
        assertThat(SessionUtils.getState(req), is("1234567890"));
    }

    @Test
    public void shouldGetNullStateIfMissing() throws Exception {
        assertThat(SessionUtils.getState(req), is(nullValue()));
    }

    @Test
    public void shouldRemoveState() throws Exception {
        SessionUtils.removeState(req);
        verify(session).removeAttribute("state");
    }

    @Test
    public void shouldSetState() throws Exception {
        SessionUtils.setState(req, "newState");
        verify(session).setAttribute("state", "newState");
    }

}