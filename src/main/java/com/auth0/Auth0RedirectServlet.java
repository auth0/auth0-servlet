package com.auth0;

import com.auth0.example.Auth0MVCProvider;
import com.auth0.lib.Auth0MVC;
import com.auth0.lib.ProcessorException;
import com.auth0.lib.SessionUtils;
import com.auth0.lib.Tokens;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import static com.auth0.ConfigUtils.readLocalRequiredParameter;

/**
 * The Servlet endpoint used as the callback handler in the OAuth 2.0 authorization code grant flow.
 * It will be called with the authorization code after a successful login.
 */
@SuppressWarnings("WeakerAccess")
public class Auth0RedirectServlet extends HttpServlet {

    private String redirectOnSuccess;
    private String redirectOnFail;
    private Auth0MVC auth0MVC;


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

        try {
            auth0MVC = Auth0MVCProvider.getInstance(config);
        } catch (UnsupportedEncodingException e) {
            throw new ServletException("Couldn't create the Auth0MVC instance. Check the configuration.", e);
        }
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
        try {
            Tokens tokens = auth0MVC.handle(req);
            SessionUtils.set(req, "accessToken", tokens.getAccessToken());
        } catch (ProcessorException e) {
            e.printStackTrace();
            res.sendRedirect(req.getContextPath() + redirectOnFail);
            return;
        }
        res.sendRedirect(req.getContextPath() + redirectOnSuccess);
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
        try {
            Tokens tokens = auth0MVC.handle(req);
            SessionUtils.set(req, "accessToken", tokens.getAccessToken());
        } catch (ProcessorException e) {
            e.printStackTrace();
            res.sendRedirect(req.getContextPath() + redirectOnFail);
            return;
        }
        res.sendRedirect(req.getContextPath() + redirectOnSuccess);
    }

}
