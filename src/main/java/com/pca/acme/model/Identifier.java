package com.pca.acme.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * ACME Identifier 모델 클래스
 * RFC 8555 §7.4 Identifier Objects 구현
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Identifier {

    /**
     * 식별자 타입 (예: "dns")
     */
    private String type;

    /**
     * 식별자 값 (예: "example.com")
     */
    private String value;
}