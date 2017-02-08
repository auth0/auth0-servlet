package com.auth0;

import com.auth0.client.auth.AuthAPI;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.auth0.ServletUtils.readConfigParameter;

/**
 * The Servlet endpoint used as the callback handler in the OAuth 2.0 authorization code grant flow.
 * This servlet will be called from Auth0 with the authorization code after a successful login.
 */
public class Auth0RedirectServlet extends HttpServlet implements TokensCallback {

    private AuthRequestProcessor authRequestProcessor;
    private String redirectOnSuccess;
    private String redirectOnFail;

    @SuppressWarnings("WeakerAccess")
    Auth0RedirectServlet(AuthRequestProcessor authRequestProcessor) {
        this.authRequestProcessor = authRequestProcessor;
    }

    public Auth0RedirectServlet() {
        this(null);
    }

    /**
     * Initialize this servlet with required configuration
     */
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        redirectOnSuccess = readConfigParameter("com.auth0.redirect_on_success", config);
        redirectOnFail = readConfigParameter("com.auth0.redirect_on_error", config);
        if (authRequestProcessor != null) {
            return;
        }

        String clientId = readConfigParameter("com.auth0.client_id", config);
        String clientSecret = readConfigParameter("com.auth0.client_secret", config);
        String domain = readConfigParameter("com.auth0.domain", config);
        APIClientHelper clientHelper = new APIClientHelper(new AuthAPI(domain, clientId, clientSecret));
        authRequestProcessor = new AuthRequestProcessor(clientHelper, this);
    }

    @Override
    public void destroy() {
        super.destroy();
        authRequestProcessor = null;
    }

    //Visible for testing
    AuthRequestProcessor getAuthRequestProcessor() {
        return authRequestProcessor;
    }

    /**
     * Auth0 server will call the redirect_uri with the tokens using the GET method.
     *
     * @param req the received request with the tokens in the parameters.
     * @param res the response to send back to the server.
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        authRequestProcessor.process(req, res);
    }

    /**
     * Auth0 server will call the redirect_uri with the tokens using the POST method when the authorize_url included the 'response_mode=form_post' value.
     *
     * @param req the received request with the tokens in the parameters.
     * @param res the response to send back to the server.
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        //Check if POST is enabled
        authRequestProcessor.process(req, res);
    }

    @Override
    public void onSuccess(HttpServletRequest req, HttpServletResponse res, Tokens tokens) throws IOException {
        res.sendRedirect(req.getContextPath() + redirectOnSuccess);
    }

    @Override
    public void onFailure(HttpServletRequest req, HttpServletResponse res, Throwable e) throws IOException {
        res.sendRedirect(req.getContextPath() + redirectOnFail);
    }

}
