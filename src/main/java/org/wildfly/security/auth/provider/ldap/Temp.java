package org.wildfly.security.auth.provider.ldap;

import org.wildfly.security.auth.provider.CredentialSupport;

public class Temp {

    public static void main(String[] args) {
        for (CredentialSupport outer : CredentialSupport.values()) {
            for (CredentialSupport inner : CredentialSupport.values()) {
                System.out.println(String.format("%s.compareTo(%s)=%d", outer, inner, outer.compareTo(inner)));
            }
        }

    }

}
