package com.auth0;

import org.apache.commons.lang3.StringUtils;

import javax.servlet.ServletConfig;

public abstract class ServletUtils {

    /**
     * Attempts to get a property from the servlet context
     *
     * @param parameter the parameter name to lookup
     * @param config    the servlet config to search
     * @return the parameter value
     */
    static String readRequiredParameter(String parameter, ServletConfig config) {
        String initParam = config.getInitParameter(parameter);
        if (StringUtils.isNotEmpty(initParam)) {
            return initParam;
        }
        String servletContextInitParam = config.getServletContext().getInitParameter(parameter);
        if (StringUtils.isNotEmpty(servletContextInitParam)) {
            return servletContextInitParam;
        }
        throw new IllegalArgumentException(parameter + " needs to be defined");
    }

    static boolean isFlagEnabled(String key, ServletConfig config) {
        String textFlag = config.getInitParameter(key);
        return textFlag != null && textFlag.equals("true");
    }
}
