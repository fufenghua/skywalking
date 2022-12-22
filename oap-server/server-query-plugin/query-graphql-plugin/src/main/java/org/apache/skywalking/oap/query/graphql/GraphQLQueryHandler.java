/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.apache.skywalking.oap.query.graphql;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;
import com.linecorp.armeria.common.*;
import com.linecorp.armeria.common.util.SafeCloseable;
import com.linecorp.armeria.server.ServiceRequestContext;
import com.linecorp.armeria.server.annotation.Blocking;
import com.linecorp.armeria.server.annotation.Post;
import com.linecorp.armeria.server.graphql.GraphqlService;
import graphql.analysis.MaxQueryComplexityInstrumentation;
import graphql.schema.GraphQLSchema;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
public class GraphQLQueryHandler {
    private final GraphqlService graphqlService;

    private static final ObjectMapper mapper = new ObjectMapper();

    private static final TypeReference<Map<String, Object>> JSON_MAP =
            new TypeReference<Map<String, Object>>() {};

    private final Map<String,String> users=new HashMap<>();

    public GraphQLQueryHandler(
        final GraphQLQueryConfig config,
        final GraphQLSchema schema) {
        final int allowedComplexity = config.getMaxQueryComplexity();
        graphqlService =
            GraphqlService
                .builder()
                .schema(schema)
                .instrumentation(new MaxQueryComplexityInstrumentation(allowedComplexity, info -> {
                    log.warn(
                        "Aborting query because it's too complex, maximum allowed is [{}] but was [{}]",
                        allowedComplexity,
                        info.getComplexity());
                    return true;
                }))
                .build();
    }

    @Blocking
    @Post("/graphql")
    public HttpResponse graphql(
        final ServiceRequestContext ctx,
        final HttpRequest req) throws Exception {
        RequestHeaders headers=req.headers();
        String authorization=headers.get("Authorization");
        if(StringUtils.isBlank(authorization)|| "null".equals(authorization)){
            return HttpResponse.builder().unauthorized().build();
        }else{
            String user=users.get(authorization);
            if(user==null){
                return HttpResponse.builder().unauthorized().build();
            }
        }
        return graphqlService.serve(ctx, req);
    }

    @Blocking
    @Post("/doLogin")
    public HttpResponse login(
            final ServiceRequestContext ctx,
            final HttpRequest req) throws Exception {
       return HttpResponse.from(req.aggregate(ctx.eventLoop()).thenApply(aggregatedHttpRequest -> {
            try (SafeCloseable ignored = ctx.push()) {
                final String body = aggregatedHttpRequest.contentUtf8();
                if (Strings.isNullOrEmpty(body)) {
                    return HttpResponse.of(HttpStatus.BAD_REQUEST, MediaType.PLAIN_TEXT,
                            "Missing request body");
                }
                Map<String,Object> params= mapper.readValue(body, JSON_MAP);
                String username=(String)params.get("username");
                String password=(String)params.get("password");
                if("admin".equals(username)&& "admin".equals(password)){
                    String token=UUID.randomUUID().toString();
                    users.put(token,"admin");
                    return HttpResponse.builder().status(200).content(token).build();
                }else{
                    return HttpResponse.builder().status(403).content("账号密码错误").build();
                }
            }catch (Exception e) {
                throw new RuntimeException(e);
            }
        }));
    }
}
