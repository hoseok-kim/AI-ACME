package com.pca.acme.config;

import com.pca.acme.interceptor.JwsValidationInterceptor;
import com.pca.acme.interceptor.NonceValidationInterceptor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 웹 설정 클래스
 * JWS 검증 및 Nonce 검증 인터셉터 등록
 */
@Configuration
@RequiredArgsConstructor
public class WebConfig implements WebMvcConfigurer {

    private final JwsValidationInterceptor jwsValidationInterceptor;
    private final NonceValidationInterceptor nonceValidationInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // JWS 검증 인터셉터 (먼저 실행)
        registry.addInterceptor(jwsValidationInterceptor)
                .addPathPatterns("/acme/**")  // ACME 경로에만 적용
                .excludePathPatterns(
                    "/acme/directory",        // Directory 엔드포인트 제외
                    "/acme/new-nonce"         // NewNonce 엔드포인트 제외
                )
                .order(1);
        
        // Nonce 검증 인터셉터 (JWS 검증 후 실행)
        registry.addInterceptor(nonceValidationInterceptor)
                .addPathPatterns("/acme/**")  // ACME 경로에만 적용
                .order(2);
    }
} 