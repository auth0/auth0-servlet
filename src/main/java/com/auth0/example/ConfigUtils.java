package com.auth0.example;

import org.apache.commons.lang3.StringUtils;

import javax.servlet.FilterConfig;
import javax.servlet.ServletConfig;

public abstract class ConfigUtils {

    /**
     * Attempts to get a required property from the {@link ServletConfig}. If it's not present there, it will try
     * to search it in the {@link javax.servlet.ServletContext}.
     *
     * @param parameter the parameter name to lookup
     * @param config    the servlet config to search
     * @return the parameter value
     * @throws IllegalArgumentException if the required value is not present or it's empty.
     */
    public static String readRequiredParameter(String parameter, ServletConfig config) throws IllegalArgumentException {
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

    /**
     * Attempts to get a required property from the {@link ServletConfig}.
     *
     * @param parameter the parameter name to lookup
     * @param config    the servlet config to search
     * @return the parameter value
     * @throws IllegalArgumentException if the required value is not present or it's empty.
     */
    static String readLocalRequiredParameter(String parameter, ServletConfig config) throws IllegalArgumentException {
        String initParam = config.getInitParameter(parameter);
        if (StringUtils.isNotEmpty(initParam)) {
            return initParam;
        }
        throw new IllegalArgumentException(parameter + " needs to be defined");
    }

    /**
     * Attempts to get a required property from the {@link FilterConfig}.
     *
     * @param parameter the parameter name to lookup
     * @param config    the servlet config to search
     * @return the parameter value
     * @throws IllegalArgumentException if the required value is not present or it's empty.
     */
    static String readLocalRequiredParameter(String parameter, FilterConfig config) throws IllegalArgumentException {
        String initParam = config.getInitParameter(parameter);
        if (StringUtils.isNotEmpty(initParam)) {
            return initParam;
        }
        throw new IllegalArgumentException(parameter + " needs to be defined");
    }

    /**
     * Attempts to get a boolean property from the {@link ServletConfig}. The value must be 'true' for the flag to be true.
     *
     * @param name   the flag name to lookup
     * @param config the servlet config to search
     * @return whether the value was present and it's value was equal to 'true' or not.
     */
    public static boolean isFlagEnabled(String name, ServletConfig config) {
        String textFlag = config.getInitParameter(name);
        return textFlag != null && textFlag.equals("true");
    }

}
