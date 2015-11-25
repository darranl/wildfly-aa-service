/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.auth.client;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.Collection;

import javax.net.ssl.SSLContext;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.wildfly.security.permission.ElytronPermission;

/**
 * A client for consuming authentication context configurations.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AuthenticationContextConfigurationClient {

    private static final ElytronPermission CREATE_PERMISSION = new ElytronPermission("createAuthenticationContextConfigurationClient");

    /**
     * A reusable privileged action to create a new configuration client.
     */
    public static final PrivilegedAction<AuthenticationContextConfigurationClient> ACTION = AuthenticationContextConfigurationClient::new;

    /**
     * Construct a new instance.
     *
     * @throws SecurityException if the caller does not have permission to instantiate this class
     */
    public AuthenticationContextConfigurationClient() throws SecurityException {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(CREATE_PERMISSION);
        }
    }

    /**
     * Get the authentication configuration which matches the given URI, or {@link AuthenticationConfiguration#EMPTY} if there is none.
     *
     * @param uri the URI to match
     * @param authenticationContext the authentication context to examine
     * @return the matching configuration
     */
    public AuthenticationConfiguration getAuthenticationConfiguration(URI uri, ClientAuthenticationContext authenticationContext) {
        final int idx = authenticationContext.ruleMatching(uri);
        if (idx == -1) return AuthenticationConfiguration.EMPTY;
        return authenticationContext.getAuthenticationConfiguration(idx);
    }

    /**
     * Get an authentication callback handler for the given configuration.
     *
     * @param configuration the configuration
     * @return the callback handler
     */
    public CallbackHandler getCallbackHandler(AuthenticationConfiguration configuration) {
        return configuration.getCallbackHandler();
    }

    /**
     * Get the actual host to use for the given configuration and URI.
     *
     * @param uri the URI
     * @param configuration the configuration
     * @return the real host to use
     */
    public String getRealHost(URI uri, AuthenticationConfiguration configuration) {
        return configuration.getHost(uri);
    }

    /**
     * Get the actual port to use for the given configuration and URI.
     *
     * @param uri the URI
     * @param configuration the configuration
     * @return the real port to use
     */
    public int getRealPort(URI uri, AuthenticationConfiguration configuration) {
        return configuration.getPort(uri);
    }

    /**
     * Get the principal to use for the given configuration.
     *
     * @param configuration the configuration
     * @return the principal
     */
    public Principal getPrincipal(AuthenticationConfiguration configuration) {
        return configuration.getPrincipal();
    }

    /**
     * Create a SASL client using the given URI and configuration from the given SASL client factory.
     *
     * @param uri the target URI
     * @param configuration the authentication configuration
     * @param clientFactory the SASL client factory to delegate to
     * @param offeredMechanisms the available mechanisms
     * @return the SASL client, or {@code null} if no clients were available or could be configured
     */
    public SaslClient createSaslClient(URI uri, AuthenticationConfiguration configuration, SaslClientFactory clientFactory, Collection<String> offeredMechanisms) throws SaslException {
        return configuration.createSaslClient(uri, clientFactory, offeredMechanisms);
    }

    /**
     * Get the address of the destination from a URI.  The configuration may rewrite the destination as needed.
     *
     * @param uri the connection URI
     * @param configuration the authentication configuration to use
     * @param protocolDefaultPort the default port for the protocol used in the URI
     * @return the address of the destination
     */
    public InetSocketAddress getDestinationInetSocketAddress(URI uri, AuthenticationConfiguration configuration, int protocolDefaultPort) {
        return configuration.getDestinationInetAddress(uri, protocolDefaultPort);
    }

    /**
     * Get an SSL context for the given URI.
     *
     * @param configuration the authentication configuration to use
     * @return the SSL context
     * @throws NoSuchAlgorithmException if an SSL context with the configured protocol failed to be instantiated
     */
    public SSLContext getSslContext(AuthenticationConfiguration configuration) throws GeneralSecurityException {
        return configuration.createSslContext();
    }

    /**
     * Connect a plain socket to the given URI.
     *
     * @param uri the connection URI
     * @param configuration the authentication configuration to use
     * @param protocolDefaultPort the default port for the protocol used in the URI
     * @return the connected socket
     * @throws IOException if socket creation or connection fails for some reason
     */
    public Socket connect(URI uri, AuthenticationConfiguration configuration, int protocolDefaultPort) throws IOException {
        final InetSocketAddress address = getDestinationInetSocketAddress(uri, configuration, protocolDefaultPort);
        return new Socket(address.getAddress(), address.getPort());
    }
}
