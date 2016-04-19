package com.auth0.example;

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


public class PartnerLogin extends HttpServlet {

    private static final Logger logger = LogManager.getLogger(PartnerLogin.class);

    private final NonceGenerator nonceGenerator = new NonceGenerator();

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String baseUrl = Helpers.buildUrlStr(request);
        request.setAttribute("baseUrl", baseUrl);
        final String externalReturnUrl = request.getParameter("externalReturnUrl");
        if (externalReturnUrl == null) {
            response.getWriter().write("Missing required external return URL query param.");
            response.setStatus(400);
            response.flushBuffer();
            return;
        }
        if (!Helpers.isTrustedExternalReturnUrl(externalReturnUrl)) {
            response.getWriter().write("Cannot redirect to untrusted URL: " + externalReturnUrl);
            response.setStatus(400);
            response.flushBuffer();
            return;
        }
        // set this up for view page
        logger.debug("Login");
        logger.debug("Request GetServletPath: " + request.getServletPath());
        final NonceStorage nonceStorage = new RequestNonceStorage(request);
        String nonce = nonceGenerator.generateNonce();
        nonceStorage.setState(nonce);
        request.setAttribute("state", "nonce=" + nonce + "&eru=" + externalReturnUrl);
        request.setAttribute("eru", externalReturnUrl);
        // response header state only for POSTMAN - not required in real app
        response.setHeader("state", "nonce=" + nonce + "&eru=" + externalReturnUrl);
        logger.debug("Nonce (set in state): " + nonce);
        logger.debug("Eru (set in state): " + externalReturnUrl);
        request.getRequestDispatcher("/partnerLogin.jsp").forward(request, response);

    }

}

