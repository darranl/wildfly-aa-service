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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.security.auth.Subject;

import org.eclipse.microprofile.context.ManagedExecutor;
import org.junit.Test;
import org.wildfly.security.auth.principal.NamePrincipal;

import io.smallrye.context.SmallRyeManagedExecutor;

/**
 * Test case to test the correct propagation of a {@link Subject}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SubjectPropagationTest {

    @Test
    public void testPropagation() throws PrivilegedActionException {
        ExecutorService executorService = Executors.newFixedThreadPool(1);
        executorService.execute(() -> {});  // Ensure the Thread is created before we associate a Subject with this one.

        ManagedExecutor executor = ((SmallRyeManagedExecutor.Builder) ManagedExecutor.builder())
                                       .withExecutorService(executorService)
                                       .maxAsync(1)
                                       .maxQueued(1)
                                       .propagated("Subject")
                                       .build();

        String testPrincipalName = "TestUser";
        Subject subject = new Subject();
        subject.getPrincipals().add(new NamePrincipal(testPrincipalName));

        Subject.doAs(subject, (PrivilegedExceptionAction<Void>) () -> {
            Future<String> result = executor.submit(() -> {
                Subject propagatedSubject = Subject.getSubject(AccessController.getContext());
                if (propagatedSubject == null) {
                    return null;
                }
                Set<Principal> principals = propagatedSubject.getPrincipals();
                return principals.iterator().next().getName();
            });
            assertEquals("Expected Principal Name", testPrincipalName, result.get());
            return null;
        });

        executor.shutdown();
        executorService.shutdown();
    }

}
