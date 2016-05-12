package com.auth0.example;

import com.auth0.Auth0User;
import com.auth0.NonceGenerator;
import com.auth0.Tokens;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import us.monoid.json.JSONArray;
import us.monoid.json.JSONObject;
import us.monoid.web.JSONResource;
import us.monoid.web.Resty;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.RequestBody;
import okhttp3.Request;
import okhttp3.ResponseBody;
import okhttp3.MediaType;

import static us.monoid.web.Resty.content;

public class MfaSignup extends HttpServlet {

    private static final Logger logger = LogManager.getLogger(MfaSignup.class);

    protected String getUri(final String auth0Domain, final String path) {
        return String.format("https://%s%s", (String) auth0Domain, path);
    }

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        logger.debug("MfaSignup");
        final Auth0User user = Auth0User.get(request);
        if (user == null) {
            final String logoutPath = getServletContext().getInitParameter("onLogoutRedirectTo");
            response.sendRedirect(logoutPath);
        }
        request.setAttribute("user", user);
        final boolean hasMfa = Auth0UserHelper.isMfaEnabled(user);
        if (hasMfa) {
            request.getRequestDispatcher("/home").forward(request, response);
            return;
        } else {
            final HttpSession session = request.getSession(true);
            final String requestMfaNonce = request.getParameter("mfaNonce");
            final String sessionMfaNonce = (String) session.getAttribute("mfaNonce");
            if (requestMfaNonce == null || sessionMfaNonce == null) {
                request.getRequestDispatcher("/home").forward(request, response);
                return;
            } else if (!sessionMfaNonce.equals(requestMfaNonce)) {
                request.getRequestDispatcher("/home").forward(request, response);
                return;
            }

            logger.info("Registering user with MFA");
            final String auth0Domain = getServletContext().getInitParameter("auth0.domain");
            final String appMetaToken = getServletContext().getInitParameter("appMetaToken");
            final String mfaPayload = "{\"app_metadata\":{\"mfa\":true}}";
            final String accountUserId = user.getUserId();

            try {
                final String encodedAccountUserId = URLEncoder.encode(accountUserId, "UTF-8");
                final String endpoint = getUri(auth0Domain, "/api/v2/users/" + encodedAccountUserId);
                final OkHttpClient client = new OkHttpClient();
                final MediaType mediaType = MediaType.parse("application/json");
                final RequestBody body = RequestBody.create(mediaType, mfaPayload);
                final Request clientRequest = new Request.Builder()
                    .url(endpoint)
                    .patch(body)
                    .addHeader("authorization", "Bearer " + appMetaToken)
                    .addHeader("content-type", "application/json")
                    .build();
                final Response clientResponse = client.newCall(clientRequest).execute();
                if (clientResponse.code() != 200) {
                    // TODO - handle error
                    throw new IllegalStateException("Error occurred setting up MFA signup");
                }
            } catch (Exception ex) {
                throw new IllegalStateException("Error occurred setting up MFA signup: ", ex);
            }
            // end - call here
            request.getRequestDispatcher("/logout").forward(request, response);
        }
    }

}
