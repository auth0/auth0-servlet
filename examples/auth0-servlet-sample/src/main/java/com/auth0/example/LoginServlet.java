package com.auth0.example;

import com.auth0.NonceGenerator;
import com.auth0.NonceStorage;
import com.auth0.RequestNonceStorage;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class LoginServlet extends HttpServlet {

    private final NonceGenerator nonceGenerator = new NonceGenerator();

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
        final NonceStorage nonceStorage = new RequestNonceStorage(request);
        String nonce = nonceStorage.getState();
        if (nonce == null) {
            nonce = nonceGenerator.generateNonce();
            nonceStorage.setState(nonce);
        }
        final String clientId = getServletContext().getInitParameter("auth0.client_id");
        final String domain = getServletContext().getInitParameter("auth0.domain");
        request.setAttribute("clientId", clientId);
        request.setAttribute("domain", domain);
//        request.setAttribute("state", "nonce=" + nonce);
        request.setAttribute("state", nonce);
        request.getRequestDispatcher("/login.jsp").forward(request, response);
    }

}
