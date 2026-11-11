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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.Page.TotalCount;
import org.dependencytrack.common.pagination.PageToken;
import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.List;

@NullMarked
public interface PersonalAccessTokenDao extends SqlObject {
    @SqlUpdate("""
        INSERT INTO "APIKEY" ("PUBLIC_ID", "SECRET_HASH", "COMMENT", "CREATED", "EXPIRES_AT", "USER_ID", "IS_LEGACY")
        SELECT :publicId, :secretHash, :name, NOW(), :expiresAt, "ID", FALSE
          FROM "USER"
         WHERE "ID" = :userId AND "TYPE" IN ('MANAGED', 'LDAP', 'OIDC')
           AND NOT COALESCE("SUSPENDED", FALSE)
        """)
    int create(
            @Bind long userId,
            @Bind String publicId,
            @Bind String secretHash,
            @Bind String name,
            @Bind Instant expiresAt);

    @SqlUpdate("""
        DELETE FROM "APIKEY" WHERE "USER_ID" = :userId AND "PUBLIC_ID" = :publicId
        """)
    int delete(@Bind long userId, @Bind String publicId);

    record TokenRow(
            long id,
            String publicId,
            @Nullable String comment,
            Instant createdAt,
            @Nullable Instant expiresAt,
            @Nullable Instant lastUsedAt,
            long totalCount) {}

    record TokensPageToken(long lastId, TotalCount totalCount) implements PageToken {
        public TokensPageToken {
            if (lastId < 1 || totalCount == null) {
                throw new IllegalArgumentException("Invalid token cursor");
            }
        }
    }

    default Page<TokenRow> list(long userId, @Nullable String pageToken, int limit) {
        final PageTokenEncoder encoder =
                getHandle().getConfig(PaginationConfig.class).getPageTokenEncoder();
        final var decoded = encoder.decode(pageToken, TokensPageToken.class);
        final List<TokenRow> rows = getHandle()
                .createQuery("""
            SELECT "ID", "PUBLIC_ID", "COMMENT", "CREATED" AS created_at,
                   "EXPIRES_AT", "LAST_USED" AS last_used_at, COUNT(*) OVER () AS total_count
              FROM "APIKEY"
             WHERE "USER_ID" = :userId AND "ID" < :lastId
             ORDER BY "ID" DESC LIMIT :limit
            """)
                .bind("userId", userId)
                .bind("lastId", decoded == null ? Long.MAX_VALUE : decoded.lastId())
                .bind("limit", limit + 1)
                .map(ConstructorMapper.of(TokenRow.class))
                .list();
        final TotalCount total = decoded != null
                ? decoded.totalCount()
                : new TotalCount(rows.isEmpty() ? 0 : rows.getFirst().totalCount(), TotalCount.Type.EXACT);
        final List<TokenRow> page = rows.stream().limit(limit).toList();
        return new Page<>(
                page,
                encoder.encode(
                        rows.size() > limit ? new TokensPageToken(page.getLast().id(), total) : null),
                total);
    }
}
