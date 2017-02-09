package com.auth0;

import com.auth0.client.auth.AuthAPI;
import org.bouncycastle.util.io.pem.PemReader;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;

import static com.auth0.ServletUtils.*;

/**
 * The Servlet endpoint used as the callback handler in the OAuth 2.0 authorization code grant flow.
 * It will be called with the authorization code after a successful login.
 */
public class Auth0RedirectServlet extends HttpServlet implements TokensCallback {

    private AuthRequestProcessor authRequestProcessor;
    private String redirectOnSuccess;
    private String redirectOnFail;
    private boolean allowPost;

    //Visible for testing
    @SuppressWarnings("WeakerAccess")
    Auth0RedirectServlet(AuthRequestProcessor authRequestProcessor) {
        this.authRequestProcessor = authRequestProcessor;
    }

    public Auth0RedirectServlet() {
        this(null);
    }

    /**
     * Initialize this servlet with required configuration.
     * <p>
     * Parameters needed on the Local Servlet scope:
     * <ul>
     * <li>'com.auth0.redirect_on_success': where to redirect after a successful authentication.</li>
     * <li>'com.auth0.redirect_on_error': where to redirect after a failed authentication.</li>
     * </ul>
     * Parameters needed on the Local/Global Servlet scope:
     * <ul>
     * <li>'com.auth0.domain': the Auth0 domain.</li>
     * <li>'com.auth0.client_id': the Auth0 Client id.</li>
     * <li>'com.auth0.client_secret': the Auth0 Client secret.</li>
     * </ul>
     */
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        redirectOnSuccess = readLocalRequiredParameter("com.auth0.redirect_on_success", config);
        redirectOnFail = readLocalRequiredParameter("com.auth0.redirect_on_error", config);
        allowPost = isFlagEnabled("com.auth0.allow_post", config);
        if (authRequestProcessor != null) {
            return;
        }

        String domain = readRequiredParameter("com.auth0.domain", config);
        String clientId = readRequiredParameter("com.auth0.client_id", config);
        String clientSecret = readRequiredParameter("com.auth0.client_secret", config);
        APIClientHelper clientHelper = new APIClientHelper(new AuthAPI(domain, clientId, clientSecret));

        TokenVerifier verifier = null;
        boolean implicitGrantEnabled = isFlagEnabled("com.auth0.use_implicit_grant", config);
        if (!implicitGrantEnabled) {
            String rs256Certificate = config.getInitParameter("com.auth0.certificate");
            if (rs256Certificate == null) {
                try {
                    verifier = new TokenVerifier(clientSecret, clientId, domain);
                } catch (UnsupportedEncodingException e) {
                    throw new ServletException("Missing UTF-8 encoding support.", e);
                }
            } else {
                byte[] keyBytes;
                try {
                    keyBytes = new PemReader(new StringReader(rs256Certificate)).readPemObject().getContent();
                    verifier = new TokenVerifier(readPublicKey(keyBytes), clientId, domain);
                } catch (IOException e) {
                    throw new ServletException("The PublicKey certificate for RS256 algorithm was invalid.", e);
                }
            }
        }
        authRequestProcessor = new AuthRequestProcessor(clientHelper, verifier, this);
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
     * Process a call to the redirect_uri with a GET HTTP method.
     *
     * @param req the received request with the tokens (implicit grant) or the authorization code (code grant) in the parameters.
     * @param res the response to send back to the server.
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        authRequestProcessor.process(req, res);
    }


    /**
     * Process a call to the redirect_uri with a POST HTTP method. This occurs if the authorize_url included the 'response_mode=form_post' value.
     * This is disabled by default. On the Local Servlet scope you can specify the 'com.auth0.allow_post' parameter to enable this behaviour.
     *
     * @param req the received request with the tokens (implicit grant) or the authorization code (code grant) in the parameters.
     * @param res the response to send back to the server.
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        if (allowPost) {
            authRequestProcessor.process(req, res);
        } else {
            res.sendError(405);
        }
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
