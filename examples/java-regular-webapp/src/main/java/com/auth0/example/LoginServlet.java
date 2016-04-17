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

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        NonceStorage nonceStorage = new RequestNonceStorage(request);
        if (!"/favicon.ico".equals(request.getServletPath())) {
            String nonce = nonceGenerator.generateNonce();
            nonceStorage.setState(nonce);
            request.setAttribute("state", nonce);
            request.getRequestDispatcher("/login.jsp").forward(request, response);
        } else {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
    }

}
