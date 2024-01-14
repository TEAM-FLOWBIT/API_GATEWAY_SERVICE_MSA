package com.example.apigatewayservice.Filter;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.apigatewayservice.common.exception.NoAuthorizationHeaderException;
import com.example.apigatewayservice.util.JwtProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
    Environment env;
    @Autowired
    private JwtProvider jwtProvider;



    public AuthorizationHeaderFilter(Environment env,JwtProvider jwtProvider) {
        super(Config.class);
        this.env = env;
        this.jwtProvider=jwtProvider;
    }

    public static class Config {

    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            log.info("Staring jwt authorization... request is {}", exchange.getRequest());

            checkAuthorizationHeader(exchange.getRequest().getHeaders());

            String jwt = parseJwtToken(exchange.getRequest());
            validateJwtToken(jwt);

            ServerHttpRequest requestWithHeader = updateRequestHeaders(exchange.getRequest(), jwt);
            log.info("jwt authorization end ...");
            return chain.filter(exchange.mutate().request(requestWithHeader).build());
        };
    }



    private void checkAuthorizationHeader(HttpHeaders headers) {
        if (!headers.containsKey(HttpHeaders.AUTHORIZATION)) {
            throw new NoAuthorizationHeaderException("Authorization header not exist");
        }
    }

    private String parseJwtToken(ServerHttpRequest request) {
        String authorizationHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader == null) {
            throw new JWTVerificationException("JWT token not valid");
        }
        return authorizationHeader.substring(7); // Remove "Bearer "
    }

    private void validateJwtToken(String jwt) {
        if (!isJwtValid(jwt)) {
            throw new JWTVerificationException("JWT token not valid");
        }
    }

    private ServerHttpRequest updateRequestHeaders(ServerHttpRequest request, String jwt) {
        return request.mutate()
                .header("username", jwtProvider.getUserIdFromToken(jwt))
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
                .build();
    }


    private boolean isJwtValid(String jwt) {
        boolean jwtVerify = true;
        String subject = null;
        try {
            jwtVerify = jwtProvider.verifyToken(jwt);
            subject = jwtProvider.getUserIdFromToken(jwt);
        } catch (JWTVerificationException e) {
            jwtVerify = false;
        }

        return jwtVerify && subject != null;
    }





}