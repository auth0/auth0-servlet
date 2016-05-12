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
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.List;

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
        handleMfaLink(user, request);
        handleLinkDropbox(user, request);
        request.getRequestDispatcher("/home.jsp").forward(request, response);
    }

    protected void handleMfaLink(final Auth0User user, final HttpServletRequest request) {
        final boolean hasMfa = Auth0UserHelper.isMfaEnabled(user);
        final HttpSession session = request.getSession(true);
        if (!hasMfa) {
            String mfaNonce = (String) session.getAttribute("mfaNonce");
            if (mfaNonce == null) {
                mfaNonce = nonceGenerator.generateNonce();
                session.setAttribute("mfaNonce", mfaNonce);
            }
        } else {
            session.removeAttribute("mfaNonce");
        }
        request.setAttribute("hasMfa", hasMfa);
    }

    protected void handleLinkDropbox(final Auth0User user, final HttpServletRequest request) {
        final List<String> linkedAccounts = Auth0UserHelper.getLinkedAccountsInfo(user);
        boolean linkDropbox = true;
        for(String acct: linkedAccounts) {
           if (acct.contains("dropbox")) {
               linkDropbox = false;
               String [] parts = acct.split("\\|");
               if (parts.length > 1) {
                   request.setAttribute("dropboxEmail", parts[1]);
               }
            }
        }
        if (linkDropbox) {
            setNonce(request);
        }
        request.setAttribute("linkDropbox", linkDropbox);
    }

    protected void setNonce(final HttpServletRequest request) {
        final NonceStorage nonceStorage = new RequestNonceStorage(request);
        String nonce = nonceStorage.getState();
        if (nonce == null) {
            nonce = nonceGenerator.generateNonce();
            nonceStorage.setState(nonce);
        }
        request.setAttribute("state", "nonce=" + nonce);
        logger.debug("Nonce (set in state): " + nonce);
    }
}
