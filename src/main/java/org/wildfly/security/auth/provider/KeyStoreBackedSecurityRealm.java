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

package org.wildfly.security.auth.provider;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500PrivateCredential;
import java.security.cert.X509Certificate;
import org.wildfly.security.auth.SecurityIdentity;
import org.wildfly.security.auth.login.AuthenticationException;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.verifier.Verifier;
import org.wildfly.security.keystore.PasswordEntry;
import org.wildfly.security.password.Password;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class KeyStoreBackedSecurityRealm implements SecurityRealm {
    private final KeyStore keyStore;

    public KeyStoreBackedSecurityRealm(final KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    public Principal mapNameToPrincipal(final String name) {
        return new NamePrincipal(name);
    }

    public CredentialSupport getCredentialSupport(final Class<?> credentialType) {
        return credentialType.isAssignableFrom(SecretKey.class) || credentialType.isAssignableFrom(Password.class) || credentialType.isAssignableFrom(X500PrivateCredential.class) ? CredentialSupport.POSSIBLY_SUPPORTED : CredentialSupport.UNSUPPORTED;
    }

    private KeyStore.Entry getEntry(Principal principal) {
        try {
            return keyStore.getEntry(principal.getName(), null);
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (UnrecoverableEntryException e) {
            return null;
        } catch (KeyStoreException e) {
            return null;
        }
    }

    public CredentialSupport getCredentialSupport(final Principal principal, final Class<?> credentialType) {
        final KeyStore.Entry entry = getEntry(principal);
        if (entry == null) {
            return CredentialSupport.UNSUPPORTED;
        }
        if (entry instanceof PasswordEntry) {
            final Password password = ((PasswordEntry) entry).getPassword();
            if (credentialType.isInstance(password)) {
                return CredentialSupport.SUPPORTED;
            } else {
                return CredentialSupport.UNSUPPORTED;
            }
        } else if (entry instanceof KeyStore.PrivateKeyEntry) {
            final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
            final PrivateKey privateKey = privateKeyEntry.getPrivateKey();
            final Certificate certificate = privateKeyEntry.getCertificate();
            return credentialType.isInstance(privateKey) || credentialType.isInstance(certificate) || certificate instanceof X509Certificate && X500PrivateCredential.class.isAssignableFrom(credentialType) ? CredentialSupport.SUPPORTED : CredentialSupport.UNSUPPORTED;
        } else if (entry instanceof KeyStore.TrustedCertificateEntry) {
            return credentialType.isInstance(((KeyStore.TrustedCertificateEntry) entry).getTrustedCertificate()) ? CredentialSupport.SUPPORTED : CredentialSupport.UNSUPPORTED;
        } else if (entry instanceof KeyStore.SecretKeyEntry) {
            return credentialType.isInstance(((KeyStore.SecretKeyEntry) entry).getSecretKey()) ? CredentialSupport.SUPPORTED : CredentialSupport.UNSUPPORTED;
        }
        return CredentialSupport.UNSUPPORTED;
    }

    public <C> C getCredential(final Class<C> credentialType, final Principal principal) {
        final KeyStore.Entry entry = getEntry(principal);
        if (entry == null) return null;
        if (entry instanceof PasswordEntry) {
            final Password password = ((PasswordEntry) entry).getPassword();
            if (credentialType.isInstance(password)) {
                return credentialType.cast(password);
            }
        } else if (entry instanceof KeyStore.PrivateKeyEntry) {
            final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
            final PrivateKey privateKey = privateKeyEntry.getPrivateKey();
            final Certificate certificate = privateKeyEntry.getCertificate();
            if (credentialType.isInstance(privateKey)) {
                return credentialType.cast(privateKey);
            } else if (credentialType.isInstance(certificate)) {
                return credentialType.cast(certificate);
            } else if (credentialType.isAssignableFrom(X500PrivateCredential.class) && certificate instanceof X509Certificate) {
                return credentialType.cast(new X500PrivateCredential((X509Certificate) certificate, privateKey, principal.getName()));
            }
        } else if (entry instanceof KeyStore.TrustedCertificateEntry) {
            final Certificate certificate = ((KeyStore.TrustedCertificateEntry) entry).getTrustedCertificate();
            if (credentialType.isInstance(certificate)) {
                return credentialType.cast(certificate);
            }
        } else if (entry instanceof KeyStore.SecretKeyEntry) {
            final SecretKey secretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
            if (credentialType.isInstance(secretKey)) {
                return credentialType.cast(secretKey);
            }
        }
        return null;
    }

    public <P> P proveAuthentic(final Principal principal, final Verifier<P> verifier) throws AuthenticationException {
        final KeyStore.Entry entry = getEntry(principal);
        if (entry == null) {
            throw new AuthenticationException();
        }
        if (entry instanceof PasswordEntry) {
            return verifier.performVerification(((PasswordEntry) entry).getPassword());
        } else if (entry instanceof KeyStore.PrivateKeyEntry) {
            final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
            final PrivateKey privateKey = privateKeyEntry.getPrivateKey();
            final Certificate certificate = privateKeyEntry.getCertificate();
            for (Class<?> credentialType : verifier.getSupportedCredentialTypes()) {
                if (credentialType.isInstance(privateKey)) {
                    return verifier.performVerification(privateKey);
                } else if (credentialType.isInstance(certificate)) {
                    return verifier.performVerification(certificate);
                } else if (credentialType.isAssignableFrom(X500PrivateCredential.class) && certificate instanceof X509Certificate) {
                    return verifier.performVerification(new X500PrivateCredential((X509Certificate) certificate, privateKey, principal.getName()));
                }
            }
        } else if (entry instanceof KeyStore.TrustedCertificateEntry) {
            return verifier.performVerification(((KeyStore.TrustedCertificateEntry) entry).getTrustedCertificate());
        } else if (entry instanceof KeyStore.SecretKeyEntry) {
            return verifier.performVerification(((KeyStore.SecretKeyEntry) entry).getSecretKey());
        }
        throw new AuthenticationException();
    }

    public SecurityIdentity createSecurityIdentity(final Principal principal) {
        return null;
    }
}
