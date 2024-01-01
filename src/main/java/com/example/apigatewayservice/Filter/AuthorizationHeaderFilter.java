package com.example.apigatewayservice.Filter;



import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.apigatewayservice.common.exception.NoAuthorizationHeaderException;
import com.example.apigatewayservice.util.JwtProvider;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.cookie.Cookie;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.server.ResponseStatusException;


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
            System.out.println("들");
            ServerHttpRequest request = exchange.getRequest();

            HttpHeaders headers = request.getHeaders();

            //프론트에서 요청을 쏠 때, Authorization header에 토큰이 담겨 있어야 한다.
            if (!headers.containsKey(HttpHeaders.AUTHORIZATION)) {
                throw new NoAuthorizationHeaderException("authorization header not exist");
            }

            String jwt = exchange.getRequest().getHeaders().get("Authorization").get(0).substring(7);   // 헤더의 토큰 파싱 (Bearer 제거)
            System.out.println(jwt);
            if(exchange.getRequest().getHeaders().get("Authorization")==null){
                throw new JWTVerificationException("jwt token not valid");
            }

            if (!isJwtValid(jwt)) {
                throw new JWTVerificationException("jwt token not valid");
            }
            System.out.println("새로운 리퀘스트 생성 중");

            ServerHttpRequest requestWithHeader = request.mutate()
                    .header("username", jwtProvider.getUserIdFromToken(jwt))
                    .header("Authorization", "Bearer " + jwt)
                    .build();

            System.out.println("테스트"+jwt);
//            return chain.filter(exchange);
            return chain.filter(exchange.mutate().request(requestWithHeader).build());
        };
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

        if (!jwtVerify || subject==null) {
            jwtVerify = false;
        }

        return jwtVerify;
    }





}