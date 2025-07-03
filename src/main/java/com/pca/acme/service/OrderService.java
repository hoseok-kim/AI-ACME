package com.pca.acme.service;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.pca.acme.dto.order.OrderRequest;
import com.pca.acme.dto.order.OrderResponse;
import com.pca.acme.model.Authorization;
import com.pca.acme.model.Identifier;
import com.pca.acme.model.Order;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * ACME Order 관리 서비스
 * RFC 8555 §7.4 Order Objects 구현
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OrderService {

    private final Map<String, Order> orders = new ConcurrentHashMap<>();
    private final AuthorizationService authorizationService;

    @Value("${acme.base-url:https://localhost:8443/acme}")
    private String baseUrl;

    @Value("${acme.order.expiration-hours:24}")
    private int orderExpirationHours;

    @Value("${acme.order.max-identifiers:100}")
    private int maxIdentifiers;

    // DNS 도메인 이름 검증을 위한 정규식
    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
        "^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+" +
        "[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?$|" +
        "^\\*\\.[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*$|" +
        "^[\\p{L}\\p{N}](?:[\\p{L}\\p{N}\\-]{0,61}[\\p{L}\\p{N}])?(?:\\.[\\p{L}\\p{N}](?:[\\p{L}\\p{N}\\-]{0,61}[\\p{L}\\p{N}])?)*$"
    );

    /**
     * 새로운 주문을 생성합니다.
     */
    public Order createOrder(String accountId, OrderRequest request) {
        log.info("Creating new order for account: {}", accountId);
        log.info("Request identifiers: {}", request.getIdentifiers());

        // 요청 검증
        validateOrderRequest(request);
        log.info("Order request validation passed");

        // 주문 생성
        String orderId = generateOrderId();
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(orderExpirationHours * 3600L);

        List<Identifier> identifiers = request.getIdentifiers().stream()
            .map(id -> Identifier.builder()
                .type(id.getType())
                .value(id.getValue())
                .build())
            .collect(Collectors.toList());

        // 인증 생성 및 URL 생성
        log.info("Creating authorizations for {} identifiers", identifiers.size());
        List<Authorization> authorizationList = authorizationService.createAuthorizations(identifiers);
        log.info("Created {} authorizations", authorizationList.size());

        List<String> authorizations = authorizationList.stream()
            .map(auth -> {
                log.info("Processing authorization: {}", auth.getAuthorizationId());
                return authorizationService.getAuthorizationUrl(auth.getAuthorizationId());
            })
            .collect(Collectors.toList());
        log.info("Generated {} authorization URLs", authorizations.size());

        Order order = Order.builder()
            .orderId(orderId)
            .accountId(accountId)
            .status(Order.OrderStatus.PENDING)
            .createdAt(now)
            .expires(expiresAt)
            .updatedAt(now)
            .identifiers(identifiers)
            .authorizations(authorizations)
            .finalize(baseUrl + "/order/" + orderId + "/finalize")
            .build();

        orders.put(orderId, order);

        log.info("Created order {} with {} identifiers", orderId, identifiers.size());
        return order;
    }

    /**
     * 주문 ID로 주문을 조회합니다.
     */
    public Order getOrder(String orderId) {
        return orders.get(orderId);
    }

    /**
     * 주문을 OrderResponse DTO로 변환합니다.
     */
    public OrderResponse toOrderResponse(Order order) {
        List<OrderResponse.Identifier> identifiers = order.getIdentifiers().stream()
            .map(id -> OrderResponse.Identifier.builder()
                .type(id.getType())
                .value(id.getValue())
                .build())
            .collect(Collectors.toList());

        return OrderResponse.builder()
            .status(order.getStatus().getValue())
            .expires(order.getExpires())
            .identifiers(identifiers)
            .authorizations(order.getAuthorizations())
            .finalize(order.getFinalize())
            .certificate(order.getCertificate())
            .build();
    }

    /**
     * 주문 요청을 검증합니다.
     */
    private void validateOrderRequest(OrderRequest request) {
        if (request.getIdentifiers() == null || request.getIdentifiers().isEmpty()) {
            if (request.getIdentifiers() == null) {
                throw new IllegalArgumentException("Missing 'identifiers' field");
            } else {
                throw new IllegalArgumentException("At least one identifier is required");
            }
        }

        if (request.getIdentifiers().size() > maxIdentifiers) {
            throw new IllegalArgumentException("Too many identifiers (maximum " + maxIdentifiers + " allowed)");
        }

        Set<String> seenIdentifiers = new java.util.HashSet<>();

        for (OrderRequest.Identifier identifier : request.getIdentifiers()) {
            validateIdentifier(identifier);

            String key = (identifier.getType() != null ? identifier.getType() : "") + ":" +
                        (identifier.getValue() != null ? identifier.getValue() : "");
            if (seenIdentifiers.contains(key)) {
                throw new IllegalArgumentException("Duplicate identifier: " + identifier.getValue());
            }
            seenIdentifiers.add(key);
        }
    }

    /**
     * 개별 식별자를 검증합니다.
     */
    private void validateIdentifier(OrderRequest.Identifier identifier) {
        if (identifier.getType() == null || identifier.getType().trim().isEmpty()) {
            throw new IllegalArgumentException("Identifier missing 'type' field");
        }

        if (identifier.getValue() == null || identifier.getValue().trim().isEmpty()) {
            if (identifier.getValue() == null) {
                throw new IllegalArgumentException("Identifier missing 'value' field");
            } else {
                throw new IllegalArgumentException("Domain name cannot be empty");
            }
        }

        // 현재는 DNS 타입만 지원
        if (!"dns".equals(identifier.getType())) {
            throw new UnsupportedOperationException("Unsupported identifier type: " + identifier.getType());
        }

        validateDomainName(identifier.getValue());
    }

    /**
     * 도메인 이름을 검증합니다.
     */
    private void validateDomainName(String domain) {
        if (domain.length() > 255) {
            throw new IllegalArgumentException("Domain name too long: " + domain);
        }

        // 기본적인 도메인 형식 검증 (와일드카드 및 국제 도메인 지원)
        if (!DOMAIN_PATTERN.matcher(domain).matches()) {
            // 간단한 추가 검증
            if (domain.contains("..") || domain.startsWith(".") || domain.endsWith(".")) {
                throw new IllegalArgumentException("Invalid domain name: " + domain);
            }
        }
    }

    /**
     * 주문 ID를 생성합니다.
     */
    private String generateOrderId() {
        return UUID.randomUUID().toString().replace("-", "");
    }



    /**
     * 주문 URL을 생성합니다.
     */
    public String getOrderUrl(String orderId) {
        return baseUrl + "/order/" + orderId;
    }
}