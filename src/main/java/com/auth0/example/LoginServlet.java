package com.auth0.example;


import com.auth0.client.auth.AuthAPI;
import com.auth0.lib.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class LoginServlet extends HttpServlet {

    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse res) throws ServletException, IOException {
        String callbackPath = getServletConfig().getInitParameter("com.auth0.onLoginRedirectTo");
        String clientId = getServletContext().getInitParameter("com.auth0.client_id");
        String clientDomain = getServletContext().getInitParameter("com.auth0.domain");
        String clientSecret = getServletContext().getInitParameter("com.auth0.client_secret");

        String state = ServletUtils.secureRandomString();
        ServletUtils.setSessionState(req, state);

        AuthAPI authAPIClient = new AuthAPI(clientDomain, clientId, clientSecret);
        String redirectUri = req.getScheme() + "://" + req.getServerName() + ":" + req.getServerPort() + callbackPath;
        String authorizeUrl = authAPIClient
                .authorizeUrl(redirectUri)
                .withState(state)
                .build();
        res.sendRedirect(authorizeUrl);
    }

}
