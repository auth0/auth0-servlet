package com.auth0.example;

import com.auth0.Auth0User;
import com.auth0.NonceGenerator;
import com.auth0.NonceStorage;
import com.auth0.RequestNonceStorage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class Home extends HttpServlet {

    private static final Logger logger = LogManager.getLogger(Home.class);

    private final NonceGenerator nonceGenerator = new NonceGenerator();

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        logger.debug("Home");
        final Auth0User user = Auth0User.get(request);
        if (user == null) {
            final String logoutPath = getServletContext().getInitParameter("onLogoutRedirectTo");
            response.sendRedirect(logoutPath);
        }
        request.setAttribute("user", user);
        final boolean linkDropBox = Auth0UserHelper.isSmsAuth0User(user);
        if (linkDropBox) {
            final NonceStorage nonceStorage = new RequestNonceStorage(request);
            String nonce = nonceStorage.getState();
            if (nonce == null) {
                nonce = nonceGenerator.generateNonce();
                nonceStorage.setState(nonce);
            }
            request.setAttribute("state", "nonce=" + nonce);
            logger.debug("Nonce (set in state): " + nonce);
        }
        request.setAttribute("linkDropBox", linkDropBox);
        request.getRequestDispatcher("/home.jsp").forward(request, response);

    }
}
