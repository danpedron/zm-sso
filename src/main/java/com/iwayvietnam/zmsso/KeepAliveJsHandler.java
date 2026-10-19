package com.iwayvietnam.zmsso;

import com.iwayvietnam.zmsso.util.Log;
import com.zimbra.cs.extension.ExtensionHttpHandler;
import java.io.IOException;
import java.io.InputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.io.IOUtils;

/**
 * Serves the {@code sso-keepalive.js} resource when
 * {@code oidc.sessionSync.enabled=true}.
 * <p>
 * Registered at {@code /service/extension/sso/keepalive.js}. The JavaScript
 * file periodically calls the {@code /sso/keepalive} endpoint to refresh
 * the OIDC access token and keep the Keycloak SSO session alive.
 * </p>
 */
public class KeepAliveJsHandler
extends ExtensionHttpHandler {
    public static final String HANDLER_PATH = "/sso/keepalive.js";
    private static final String JS_RESOURCE = "sso-keepalive.js";

    public String getPath() {
        return HANDLER_PATH;
    }

    @Override
    public void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException {
        InputStream inputStream = KeepAliveJsHandler.class.getResourceAsStream("/" + JS_RESOURCE);
        if (inputStream == null) {
            Log.sso.warn("KeepAliveJs: resource not found: " + JS_RESOURCE);
            httpServletResponse.setStatus(404);
            return;
        }
        httpServletResponse.setContentType("application/javascript; charset=UTF-8");
        httpServletResponse.setCharacterEncoding("UTF-8");
        IOUtils.copy(inputStream, httpServletResponse.getOutputStream());
        inputStream.close();
    }

    @Override
    public void doPost(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException {
        this.doGet(httpServletRequest, httpServletResponse);
    }
}
