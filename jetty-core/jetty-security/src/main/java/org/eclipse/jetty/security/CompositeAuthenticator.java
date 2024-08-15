package org.eclipse.jetty.security;

import java.security.Principal;
import java.util.function.Function;

import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.http.pathmap.MatchedResource;
import org.eclipse.jetty.http.pathmap.PathMappings;
import org.eclipse.jetty.security.authentication.LoginAuthenticator;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.Session;
import org.eclipse.jetty.util.Callback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CompositeAuthenticator extends LoginAuthenticator
{
    private static final Logger LOG = LoggerFactory.getLogger(CompositeAuthenticator.class);

    private static final String AUTH_NAME_ATTR = "authNameAttribute";
    private static final String LOG_IN_ATTR = "isLoggedIn";
    private static final DefaultAuthenticator DEFAULT_AUTHENTICATOR = new DefaultAuthenticator();
    private final PathMappings<Authenticator> _authenticatorsMappings = new PathMappings<>();

    public void addAuthenticator(String pathSpec, Authenticator authenticator)
    {
        _authenticatorsMappings.put(pathSpec, authenticator);
    }

    @Override
    public void setConfiguration(Configuration configuration)
    {
        for (Authenticator authenticator : _authenticatorsMappings.values())
        {
            authenticator.setConfiguration(configuration);
        }
        super.setConfiguration(configuration);
    }

    @Override
    public LoginService getLoginService()
    {
        return super.getLoginService();
    }



    @Override
    protected void updateSession(Request httpRequest, Response httpResponse)
    {
        super.updateSession(httpRequest, httpResponse);
    }

    @Override
    public UserIdentity login(String username, Object password, Request request, Response response)
    {
        Authenticator authenticator = getAuthenticator(request);
        if (authenticator instanceof LoginAuthenticator loginAuthenticator)
        {
            UserIdentity userIdentity = loginAuthenticator.login(username, password, request, response);
            if (userIdentity != null)
                doLogin(request);
        }
        return null;
    }

    @Override
    public void logout(Request request, Response response)
    {
        Authenticator authenticator = getAuthenticator(request);
        if (authenticator instanceof LoginAuthenticator loginAuthenticator)
            loginAuthenticator.logout(request, response);
        doLogout(request);
    }

    @Override
    public String getAuthenticationType()
    {
        return "COMPOSITE";
    }

    @Override
    public Constraint.Authorization getConstraintAuthentication(String pathInContext, Constraint.Authorization existing, Function<Boolean, Session> getSession)
    {
        Session session = getSession.apply(true);

        // If we are logged in we should always use that authenticator until logged out.
        if (isLoggedIn(session))
        {
            Authenticator authenticator = getAuthenticator(session);
            return authenticator.getConstraintAuthentication(pathInContext, existing, getSession);
        }

        Authenticator authenticator = null;
        MatchedResource<Authenticator> matched = _authenticatorsMappings.getMatched(pathInContext);
        if (matched != null)
            authenticator = matched.getResource();
        if (authenticator == null)
            authenticator = getAuthenticator(session);
        if (authenticator == null)
            authenticator = DEFAULT_AUTHENTICATOR;
        saveAuthenticator(session, authenticator);
        return authenticator.getConstraintAuthentication(pathInContext, existing, getSession);
    }

    @Override
    public AuthenticationState validateRequest(Request request, Response response, Callback callback) throws ServerAuthException
    {
        Session session = request.getSession(true);
        Authenticator authenticator = getAuthenticator(session);
        if (authenticator == null)
        {
            Response.writeError(request, response, callback, HttpStatus.FORBIDDEN_403);
            return AuthenticationState.SEND_FAILURE;
        }

        // Wrap the successful authentication state to intercept the logout request to clear the session attribute.
        AuthenticationState authenticationState = authenticator.validateRequest(request, response, callback);
        if (authenticationState instanceof AuthenticationState.Succeeded succeededState)
        {
            // The authenticator may have logged in a user with its login service directly without going through the
            // AuthenticationState login methods, or the login methods on this LoginAuthenticator.
            // TODO: maybe we need a custom login service to act as an interception point for login/logout.
            if (succeededState instanceof UserAuthenticationSent)
                doLogin(request);
            return new CompositeSucceededAuthenticationState(succeededState);
        }
        else if (authenticationState instanceof AuthenticationState.Deferred deferredState)
            return new CompositeDelegateAuthenticationState(deferredState);
        return authenticationState;
    }

    @Override
    public Request prepareRequest(Request request, AuthenticationState authenticationState)
    {
        Session session = request.getSession(true);
        Authenticator authenticator = getAuthenticator(session);
        if (authenticator == null)
            throw new IllegalStateException("No authenticator found");
        return authenticator.prepareRequest(request, authenticationState);
    }

    private static class CompositeDelegateAuthenticationState implements AuthenticationState.Deferred
    {
        private final AuthenticationState.Deferred _delegate;

        public CompositeDelegateAuthenticationState(AuthenticationState.Deferred state)
        {
            _delegate = state;
        }

        @Override
        public Succeeded authenticate(Request request)
        {
            return _delegate.authenticate(request);
        }

        @Override
        public AuthenticationState authenticate(Request request, Response response, Callback callback)
        {
            return _delegate.authenticate(request, response, callback);
        }

        @Override
        public Succeeded login(String username, Object password, Request request, Response response)
        {
            Succeeded succeeded = _delegate.login(username, password, request, response);
            if (succeeded != null)
                doLogin(request);
            return succeeded;
        }

        @Override
        public void logout(Request request, Response response)
        {
            _delegate.logout(request, response);
            doLogout(request);
        }

        @Override
        public IdentityService.Association getAssociation()
        {
            return _delegate.getAssociation();
        }

        @Override
        public Principal getUserPrincipal()
        {
            return _delegate.getUserPrincipal();
        }
    }

    private static class CompositeSucceededAuthenticationState implements AuthenticationState.Succeeded
    {
        private final AuthenticationState.Succeeded _delegate;

        public CompositeSucceededAuthenticationState(AuthenticationState.Succeeded state)
        {
            _delegate = state;
        }

        @Override
        public String getAuthenticationType()
        {
            return _delegate.getAuthenticationType();
        }

        @Override
        public UserIdentity getUserIdentity()
        {
            return _delegate.getUserIdentity();
        }

        @Override
        public Principal getUserPrincipal()
        {
            return _delegate.getUserPrincipal();
        }

        @Override
        public boolean isUserInRole(String role)
        {
            return _delegate.isUserInRole(role);
        }

        @Override
        public void logout(Request request, Response response)
        {
            _delegate.logout(request, response);
            doLogout(request);
        }
    }

    private static class DefaultAuthenticator implements Authenticator
    {

        @Override
        public void setConfiguration(Configuration configuration)
        {
        }

        @Override
        public String getAuthenticationType()
        {
            return "DEFAULT";
        }

        @Override
        public AuthenticationState validateRequest(Request request, Response response, Callback callback) throws ServerAuthException
        {
            return null;
        }
    }

    private static boolean isLoggedIn(Session session)
    {
        return session != null && Boolean.TRUE.equals(session.getAttribute(LOG_IN_ATTR));
    }

    private static void doLogin(Request request)
    {
        Session session = request.getSession(true);
        if (session != null)
        {
            session.setAttribute(LOG_IN_ATTR, Boolean.TRUE);
        }
    }

    private static void doLogout(Request request)
    {
        Session session = request.getSession(false);
        if (session != null)
        {
            session.removeAttribute(AUTH_NAME_ATTR);
            session.removeAttribute(LOG_IN_ATTR);
        }
    }

    private void saveAuthenticator(Session session, Authenticator authenticator)
    {
        session.setAttribute(AUTH_NAME_ATTR, authenticator.getClass().getSimpleName());
    }

    private Authenticator getAuthenticator(Request request)
    {
        return getAuthenticator(request.getSession(true));
    }

    private Authenticator getAuthenticator(Session session)
    {
        if (session == null)
            return null;

        String name = (String)session.getAttribute(AUTH_NAME_ATTR);
        if (name == null)
            return null;

        if (DEFAULT_AUTHENTICATOR.getClass().getSimpleName().equals(name))
            return DEFAULT_AUTHENTICATOR;
        for (Authenticator authenticator : _authenticatorsMappings.values())
        {
            if (name.equals(authenticator.getClass().getSimpleName()))
                return authenticator;
        }

        return null;
    }
}
