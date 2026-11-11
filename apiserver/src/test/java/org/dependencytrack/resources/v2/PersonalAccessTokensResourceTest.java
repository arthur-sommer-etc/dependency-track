/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.resources.v2;

import alpine.model.ManagedUser;
import alpine.model.auth.UserType;
import alpine.server.auth.SessionTokenService;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.jdbi.PersonalAccessTokenDao;
import org.dependencytrack.persistence.jdbi.ServiceAccountDao;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class PersonalAccessTokensResourceTest extends ResourceTest {
    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(new ResourceConfig());

    private static final String PATH = "/users/me/personal-access-tokens";
    private ManagedUser user;
    private String session;

    @BeforeEach
    void createUserSession() {
        user = qm.createManagedUser("alice", TEST_USER_PASSWORD_HASH);
        session = new SessionTokenService().createSession(user.getId());
    }

    private Response create(String body) {
        return jersey.target(PATH)
                .request()
                .header("Authorization", "Bearer " + session)
                .post(Entity.json(body));
    }

    @Test
    void shouldCreateNamedTokenRevealSecretOnceAndRevokeOnlyOwnToken() {
        final Response created = create("{\"comment\":\"My script\",\"expires_in_days\":7}");
        assertThat(created.getStatus()).isEqualTo(201);
        assertThat(created.getHeaderString("Cache-Control")).contains("no-store");
        final JsonObject token = parseJsonObject(created);
        final String publicId = token.getString("public_id");
        final String secret = token.getString("key");
        assertThat(secret).contains(publicId);
        final var stored = withJdbiHandle(
                handle -> handle.createQuery("SELECT \"SECRET_HASH\" FROM \"APIKEY\" WHERE \"PUBLIC_ID\" = :id")
                        .bind("id", publicId)
                        .mapTo(String.class)
                        .one());
        assertThat(stored).hasSize(64).isNotEqualTo(secret);
        final Response listed = jersey.target(PATH)
                .request()
                .header("Authorization", "Bearer " + session)
                .get();
        assertThat(listed.getStatus()).isEqualTo(200);
        final String listBody = getPlainTextBody(listed);
        assertThat(listBody).contains("My script", publicId).doesNotContain(secret, stored, "secret_hash", "\"key\"");
        final var bob = qm.createManagedUser("bob", TEST_USER_PASSWORD_HASH);
        final String bobSession = new SessionTokenService().createSession(bob.getId());
        assertThat(jersey.target(PATH)
                        .path(publicId)
                        .request()
                        .header("Authorization", "Bearer " + bobSession)
                        .delete()
                        .getStatus())
                .isEqualTo(404);
        assertThat(jersey.target(PATH)
                        .request()
                        .header("Authorization", "Bearer " + bobSession)
                        .get(String.class))
                .doesNotContain(publicId);
        assertThat(jersey.target(PATH)
                        .path(publicId)
                        .request()
                        .header("Authorization", "Bearer " + session)
                        .delete()
                        .getStatus())
                .isEqualTo(204);
        assertThat(jersey.target(PATH).request().header(X_API_KEY, secret).get().getStatus())
                .isEqualTo(401);
    }

    @Test
    void shouldRequireHumanSessionEvenForAdministratorsAndPersonalTokens() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);
        assertThat(jersey.target(PATH).request().get().getStatus()).isEqualTo(401);
        assertThat(jersey.target(PATH).request().header(X_API_KEY, apiKey).get().getStatus())
                .isEqualTo(403);
        qm.addUserToTeam(user, team);
        final JsonObject createdToken = parseJsonObject(create("{\"comment\":\"script\"}"));
        final String pat = createdToken.getString("key");
        assertThat(jersey.target(PATH)
                        .path(createdToken.getString("public_id"))
                        .request()
                        .header(X_API_KEY, pat)
                        .delete()
                        .getStatus())
                .isEqualTo(403);
        assertThat(jersey.target(PATH)
                        .request()
                        .header(X_API_KEY, pat)
                        .post(Entity.json("{\"comment\":\"replacement\"}"))
                        .getStatus())
                .isEqualTo(403);
        assertThat(jersey.target(PATH).request().header(X_API_KEY, pat).get().getStatus())
                .isEqualTo(403);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "{}",
                "{\"comment\":\" \"}",
                "{\"comment\":\"script\",\"expires_in_days\":0}",
                "{\"comment\":\"script\",\"expires_in_days\":367}"
            })
    void shouldRejectInvalidNamesAndLifetime(String body) {
        assertThat(create(body).getStatus()).isEqualTo(400);
    }

    @Test
    void shouldPageTokensWithoutExposingSecrets() {
        final String first = parseJsonObject(create("{\"comment\":\"first\"}")).getString("public_id");
        final String second =
                parseJsonObject(create("{\"comment\":\"second\"}")).getString("public_id");
        final JsonObject page = parseJsonObject(jersey.target(PATH)
                .queryParam("limit", 1)
                .request()
                .header("Authorization", "Bearer " + session)
                .get());
        assertThat(page.getJsonArray("items").getJsonObject(0).getString("public_id"))
                .isEqualTo(second);
        final JsonObject next = parseJsonObject(jersey.target(PATH)
                .queryParam("limit", 1)
                .queryParam("page_token", page.getString("next_page_token"))
                .request()
                .header("Authorization", "Bearer " + session)
                .get());
        assertThat(next.getJsonArray("items").getJsonObject(0).getString("public_id"))
                .isEqualTo(first);
    }

    @Test
    void shouldEnforceCurrentPermissionsAndPortfolioAccess() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        qm.addUserToTeam(user, team);
        enablePortfolioAccessControl();
        final var allowed = qm.createProject("allowed", null, null, null, null, null, null, false);
        allowed.setAccessTeams(java.util.Set.of(team));
        qm.persist(allowed);
        final var denied = qm.createProject("denied", null, null, null, null, null, null, false);
        final String pat = parseJsonObject(create("{\"comment\":\"script\"}")).getString("key");
        final String allowedPath = "/projects/" + allowed.getUuid() + "/components";
        assertThat(jersey.target(allowedPath)
                        .request()
                        .header(X_API_KEY, pat)
                        .get()
                        .getStatus())
                .isEqualTo(200);
        assertThat(jersey.target("/projects/" + denied.getUuid() + "/components")
                        .request()
                        .header(X_API_KEY, pat)
                        .get()
                        .getStatus())
                .isEqualTo(403);
        useJdbiHandle(handle -> handle.createUpdate("DELETE FROM \"USERS_TEAMS\" WHERE \"USER_ID\" = :id")
                .bind("id", user.getId())
                .execute());
        assertThat(jersey.target(allowedPath)
                        .request()
                        .header(X_API_KEY, pat)
                        .get()
                        .getStatus())
                .isEqualTo(403);
        // The original team key remains valid and retains its team's access.
        assertThat(jersey.target(allowedPath)
                        .request()
                        .header(X_API_KEY, apiKey)
                        .get()
                        .getStatus())
                .isEqualTo(200);
    }

    @Test
    void shouldRejectSuspendedOwnerAtPersistenceBoundary() {
        useJdbiHandle(handle -> handle.createUpdate("UPDATE \"USER\" SET \"SUSPENDED\" = TRUE WHERE \"ID\" = :id")
                .bind("id", user.getId())
                .execute());
        assertThat(create("{\"comment\":\"script\"}").getStatus()).isEqualTo(401);
        final int created = withJdbiHandle(handle -> handle.attach(PersonalAccessTokenDao.class)
                .create(
                        user.getId(),
                        "testkey1",
                        "hash",
                        "name",
                        java.time.Instant.now().plusSeconds(100)));
        assertThat(created).isZero();
    }

    @Test
    void shouldRejectServiceOwnerAtPersistenceBoundaryAndSessionManagement() {
        final long id = withJdbiHandle(handle -> {
            handle.attach(ServiceAccountDao.class).create("svc:test", null);
            return handle.createQuery("SELECT \"ID\" FROM \"USER\" WHERE \"USERNAME\" = 'svc:test'")
                    .mapTo(Long.class)
                    .one();
        });
        final int created = withJdbiHandle(handle -> handle.attach(PersonalAccessTokenDao.class)
                .create(id, "service1", "hash", "name", Instant.now().plusSeconds(100)));
        assertThat(created).isZero();
        session = new SessionTokenService().createSession(id);
        assertThat(create("{\"comment\":\"script\"}").getStatus()).isEqualTo(403);
        assertThat(jersey.target(PATH)
                        .request()
                        .header("Authorization", "Bearer " + session)
                        .get()
                        .getStatus())
                .isEqualTo(403);
    }

    @ParameterizedTest
    @EnumSource(
            value = UserType.class,
            names = {"LDAP", "OIDC"})
    void shouldManageTokensForExternalUserSessions(UserType type) {
        final long id =
                switch (type) {
                    case LDAP -> qm.createLdapUser("external").getId();
                    case OIDC -> qm.createOidcUser("external").getId();
                    default -> throw new IllegalArgumentException();
                };
        session = new SessionTokenService().createSession(id);
        final Response created = create("{\"comment\":\"external script\"}");
        assertThat(created.getStatus()).isEqualTo(201);
        final String publicId = parseJsonObject(created).getString("public_id");
        assertThat(jersey.target(PATH)
                        .request()
                        .header("Authorization", "Bearer " + session)
                        .get(String.class))
                .contains(publicId);
        assertThat(jersey.target(PATH)
                        .path(publicId)
                        .request()
                        .header("Authorization", "Bearer " + session)
                        .delete()
                        .getStatus())
                .isEqualTo(204);
    }

    @Test
    void shouldDefaultToThirtyDaysAndAllowMaximumLifetime() {
        final Instant before = Instant.now();
        final JsonObject token = parseJsonObject(create("{\"comment\":\"default\"}"));
        assertThat(token.getJsonNumber("expires_at").longValue())
                .isBetween(
                        before.plus(Duration.ofDays(30)).toEpochMilli(),
                        Instant.now().plus(Duration.ofDays(30)).toEpochMilli());
        assertThat(create("{\"comment\":\"maximum\",\"expires_in_days\":366}").getStatus())
                .isEqualTo(201);
    }

    @Test
    void shouldRejectInvalidPaginationAndOverlongName() {
        assertThat(jersey.target(PATH)
                        .queryParam("limit", 0)
                        .request()
                        .header("Authorization", "Bearer " + session)
                        .get()
                        .getStatus())
                .isEqualTo(400);
        assertThat(jersey.target(PATH)
                        .queryParam("page_token", "invalid")
                        .request()
                        .header("Authorization", "Bearer " + session)
                        .get()
                        .getStatus())
                .isEqualTo(400);
        assertThat(create("{\"comment\":\"" + "a".repeat(256) + "\"}").getStatus())
                .isEqualTo(400);
    }
}
