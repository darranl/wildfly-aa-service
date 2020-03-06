/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.mp.propagation;

import static org.junit.Assert.assertEquals;

import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import javax.security.auth.Subject;

import org.eclipse.microprofile.context.ManagedExecutor;
import org.junit.Test;
import org.wildfly.security.auth.principal.NamePrincipal;

/**
 * Test case to test the correct propagation of a {@link Subject}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SubjectPropagationTest {

    private static final String PRINCIPAL_NAME = "TestUser";

    @Test
    public void testPropagation() throws PrivilegedActionException {
        Subject subject = new Subject();
        subject.getPrincipals().add(new NamePrincipal(PRINCIPAL_NAME));

        Subject.doAs(subject, (PrivilegedExceptionAction<Void>) () -> {
            subjectPropagation();
            return null;
        });
    }

    public void subjectPropagation() throws InterruptedException, ExecutionException {
        ManagedExecutor executor = ManagedExecutor.builder()
                                       .propagated("Subject")
                                       .build();

        Future<String> result = executor.submit(() -> {
            Subject subject = Subject.getSubject(AccessController.getContext());
            Set<Principal> principals = subject.getPrincipals();
            return principals.iterator().next().getName();
        });
        assertEquals("Expected Principal Name", PRINCIPAL_NAME, result.get());

        executor.shutdown();
    }


}
