package com.auth0.lib;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

public class SessionUtilsTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldGetRandomString() throws Exception {
        String string = SessionUtils.secureRandomString();
        Assert.assertThat(string, is(notNullValue()));
    }

    @Test
    public void shouldGetUserId() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.getSession().setAttribute("com.auth0.userId", "theUserId");

        assertThat(SessionUtils.getSessionUserId(req), is("theUserId"));
    }

    @Test
    public void shouldGetNullUserIdIfMissing() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();

        assertThat(SessionUtils.getSessionUserId(req), is(nullValue()));
    }

    @Test
    public void shouldSetUserId() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();

        SessionUtils.setSessionUserId(req, "newUserId");
        assertThat((String) req.getSession().getAttribute("com.auth0.userId"), is("newUserId"));
    }

    @Test
    public void shouldSetState() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();

        SessionUtils.setSessionState(req, "123456");
        assertThat((String) req.getSession().getAttribute("com.auth0.state"), is("123456"));
    }

    @Test
    public void shouldAcceptBothNullStates() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        boolean validState = SessionUtils.checkSessionState(req, null);
        assertThat(validState, is(true));
    }

    @Test
    public void shouldCheckAndRemoveInvalidState() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.getSession().setAttribute("com.auth0.state", "123456");

        boolean validState = SessionUtils.checkSessionState(req, "abcdef");
        assertThat(validState, is(false));
        assertThat(req.getSession().getAttribute("com.auth0.state"), is(nullValue()));
    }

    @Test
    public void shouldCheckAndRemoveCorrectState() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.getSession().setAttribute("com.auth0.state", "123456");

        boolean validState = SessionUtils.checkSessionState(req, "123456");
        assertThat(validState, is(true));
        assertThat(req.getSession().getAttribute("com.auth0.state"), is(nullValue()));
    }

    @Test
    public void shouldSetNonce() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();

        SessionUtils.setSessionNonce(req, "123456");
        assertThat((String) req.getSession().getAttribute("com.auth0.nonce"), is("123456"));
    }

    @Test
    public void shouldGetAndRemoveNonce() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.getSession().setAttribute("com.auth0.nonce", "123456");

        String nonce = SessionUtils.removeSessionNonce(req);
        assertThat(nonce, is("123456"));
        assertThat(req.getSession().getAttribute("com.auth0.nonce"), is(nullValue()));
    }

    @Test
    public void shouldGetAndRemoveNonceIfMissing() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();

        String nonce = SessionUtils.removeSessionNonce(req);
        assertThat(nonce, is(nullValue()));
        assertThat(req.getSession().getAttribute("com.auth0.nonce"), is(nullValue()));
    }
}