package com.auth0;

import com.auth0.client.auth.AuthAPI;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import static com.auth0.ServletUtils.*;

/**
 * The Servlet endpoint used as the callback handler in the OAuth 2.0 authorization code grant flow.
 * It will be called with the authorization code after a successful login.
 */
public class Auth0RedirectServlet extends HttpServlet implements TokensCallback {

    private final RequestProcessorFactory processorFactory;
    private RequestProcessor requestProcessor;
    private String redirectOnSuccess;
    private String redirectOnFail;
    private boolean allowPost;
    private boolean useImplicitGrant;

    //Visible for testing
    @SuppressWarnings("WeakerAccess")
    Auth0RedirectServlet(RequestProcessorFactory factory) {
        this.processorFactory = factory;
    }

    public Auth0RedirectServlet() {
        this(new RequestProcessorFactory());
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

        String domain = readRequiredParameter("com.auth0.domain", config);
        String clientId = readRequiredParameter("com.auth0.client_id", config);
        String clientSecret = readRequiredParameter("com.auth0.client_secret", config);
        APIClientHelper clientHelper = new APIClientHelper(new AuthAPI(domain, clientId, clientSecret));

        useImplicitGrant = isFlagEnabled("com.auth0.use_implicit_grant", config);
        if (!useImplicitGrant) {
            requestProcessor = processorFactory.forCodeGrant(clientHelper, this);
            return;
        }
        if (!allowPost) {
            throw new ServletException("Implicit Grant can only be used with a POST method. Enable the 'com.auth0.allow_post' parameter in the Servlet configuration and make sure to request the login with the 'response_mode=form_post' parameter.");
        }

        String certificate = config.getInitParameter("com.auth0.certificate");
        if (certificate == null) {
            try {
                requestProcessor = processorFactory.forImplicitGrantHS(clientHelper, clientSecret, clientId, domain, this);
            } catch (UnsupportedEncodingException e) {
                throw new ServletException("Missing UTF-8 encoding support.", e);
            }
        } else {
            try {
                String path = config.getServletContext().getRealPath(certificate);
                requestProcessor = processorFactory.forImplicitGrantRS(clientHelper, path, clientId, domain, this);
            } catch (Exception e) {
                throw new ServletException("The PublicKey or Certificate for RS256 algorithm was invalid.", e);
            }
        }
    }

    @Override
    public void destroy() {
        super.destroy();
        requestProcessor = null;
    }

    //Visible for testing
    RequestProcessor getRequestProcessor() {
        return requestProcessor;
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
        if (!useImplicitGrant) {
            requestProcessor.process(req, res);
        } else {
            res.sendError(405);
        }
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
            requestProcessor.process(req, res);
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
