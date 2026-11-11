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

import alpine.model.ApiKey;
import alpine.model.auth.UserPrincipal;
import alpine.model.auth.UserType;
import alpine.security.ApiKeyGenerator;
import alpine.server.auth.PrincipalSecurityContext;
import org.dependencytrack.api.v2.PersonalAccessTokensApi;
import org.dependencytrack.api.v2.model.CreatePersonalAccessTokenRequest;
import org.dependencytrack.api.v2.model.CreateServiceAccountApiKeyResponse;
import org.dependencytrack.api.v2.model.ListServiceAccountApiKeysResponse;
import org.dependencytrack.api.v2.model.ServiceAccountApiKey;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.common.pagination.InvalidPageTokenException;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.persistence.jdbi.PersonalAccessTokenDao;
import org.dependencytrack.resources.AbstractApiResource;
import org.eclipse.microprofile.config.ConfigProvider;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.ws.rs.ext.Provider;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

@Provider
public final class PersonalAccessTokensResource extends AbstractApiResource implements PersonalAccessTokensApi {
    private static final Logger LOGGER = LoggerFactory.getLogger(PersonalAccessTokensResource.class);

    @Context
    private SecurityContext securityContext;

    private UserPrincipal requireUserSession() {
        if (!(getPrincipal() instanceof final UserPrincipal user)
                || user.type() == UserType.SERVICE
                || !PrincipalSecurityContext.BEARER_AUTH.equals(securityContext.getAuthenticationScheme())) {
            throw new ForbiddenException("A human user session is required to manage personal access tokens");
        }
        return user;
    }

    @Override
    public Response createPersonalAccessToken(CreatePersonalAccessTokenRequest request) {
        final UserPrincipal user = requireUserSession();
        final String name =
                request.getComment() == null ? "" : request.getComment().strip();
        if (name.isEmpty() || name.length() > 255) {
            throw new BadRequestException("A token name between 1 and 255 characters is required");
        }
        final int maxDays = ConfigProvider.getConfig().getValue(ConfigKeys.API_KEY_MAX_LIFETIME_DAYS, int.class);
        final int days = request.getExpiresInDays() == null ? Math.min(30, maxDays) : request.getExpiresInDays();
        if (days < 1 || days > maxDays) {
            throw new BadRequestException("The expiry must be between 1 and %d days".formatted(maxDays));
        }
        final Instant expiresAt = Instant.now().plus(days, ChronoUnit.DAYS);
        final ApiKey key = ApiKeyGenerator.generate();
        final int created = inJdbiTransaction(handle -> handle.attach(PersonalAccessTokenDao.class)
                .create(user.id(), key.getPublicId(), key.getSecretHash(), name, expiresAt));
        if (created == 0) {
            throw new ForbiddenException("The user is unavailable or suspended");
        }
        LOGGER.info(
                SecurityMarkers.SECURITY_AUDIT,
                "Created personal access token {} for user {}, expiring at {}",
                key.getPublicId(),
                user.username(),
                expiresAt);
        return Response.created(getUriInfo()
                        .getAbsolutePathBuilder()
                        .path(key.getPublicId())
                        .build())
                .header("Cache-Control", "no-store")
                .entity(CreateServiceAccountApiKeyResponse.builder()
                        .publicId(key.getPublicId())
                        .key(key.getKey())
                        .expiresAt(expiresAt.toEpochMilli())
                        .build())
                .build();
    }

    @Override
    public Response listPersonalAccessTokens(String pageToken, Integer limit) {
        final UserPrincipal user = requireUserSession();
        final Page<PersonalAccessTokenDao.TokenRow> page;
        try {
            page = withJdbiHandle(
                    handle -> handle.attach(PersonalAccessTokenDao.class).list(user.id(), pageToken, limit));
        } catch (InvalidPageTokenException e) {
            throw new BadRequestException("Invalid page token", e);
        }
        return Response.ok(ListServiceAccountApiKeysResponse.builder()
                        .items(page.items().stream()
                                .<ServiceAccountApiKey>map(row -> ServiceAccountApiKey.builder()
                                        .publicId(row.publicId())
                                        .comment(row.comment())
                                        .createdAt(row.createdAt().toEpochMilli())
                                        .expiresAt(
                                                row.expiresAt() == null
                                                        ? null
                                                        : row.expiresAt().toEpochMilli())
                                        .lastUsedAt(
                                                row.lastUsedAt() == null
                                                        ? null
                                                        : row.lastUsedAt().toEpochMilli())
                                        .build())
                                .toList())
                        .nextPageToken(page.nextPageToken())
                        .total(convertTotalCount(page.totalCount()))
                        .build())
                .header("Cache-Control", "no-store")
                .build();
    }

    @Override
    public Response deletePersonalAccessToken(String publicId) {
        final UserPrincipal user = requireUserSession();
        final int deleted = inJdbiTransaction(
                handle -> handle.attach(PersonalAccessTokenDao.class).delete(user.id(), publicId));
        if (deleted == 0) {
            throw new NotFoundException();
        }
        LOGGER.info(
                SecurityMarkers.SECURITY_AUDIT,
                "Revoked personal access token {} of user {}",
                publicId,
                user.username());
        return Response.noContent().build();
    }
}
