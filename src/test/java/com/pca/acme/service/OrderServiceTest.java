package com.pca.acme.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.pca.acme.dto.order.OrderRequest;
import com.pca.acme.model.Authorization;
import com.pca.acme.model.Identifier;
import com.pca.acme.model.Order;

@ExtendWith(MockitoExtension.class)
class OrderServiceTest {

    @Mock
    private AuthorizationService authorizationService;

    private OrderService orderService;

    @BeforeEach
    void setUp() {
        orderService = new OrderService(authorizationService);
        // Set fields using reflection to avoid @Value dependency
        try {
            var baseUrlField = OrderService.class.getDeclaredField("baseUrl");
            baseUrlField.setAccessible(true);
            baseUrlField.set(orderService, "https://localhost:8443/acme");

            var maxIdentifiersField = OrderService.class.getDeclaredField("maxIdentifiers");
            maxIdentifiersField.setAccessible(true);
            maxIdentifiersField.set(orderService, 100);

            var expirationHoursField = OrderService.class.getDeclaredField("orderExpirationHours");
            expirationHoursField.setAccessible(true);
            expirationHoursField.set(orderService, 24);
        } catch (Exception e) {
            // Ignore for test
        }
    }

    @Test
    void shouldCreateOrderSuccessfully() {
        // Given
        String accountId = "test-account";
        OrderRequest.Identifier identifier = new OrderRequest.Identifier();
        identifier.setType("dns");
        identifier.setValue("example.com");

        OrderRequest request = new OrderRequest();
        request.setIdentifiers(List.of(identifier));

        Authorization mockAuth = Authorization.builder()
            .authorizationId("auth123")
            .identifier(Identifier.builder().type("dns").value("example.com").build())
            .status(Authorization.AuthorizationStatus.PENDING)
            .build();

        when(authorizationService.createAuthorizations(any()))
            .thenReturn(List.of(mockAuth));
        when(authorizationService.getAuthorizationUrl("auth123"))
            .thenReturn("https://localhost:8443/acme/authz/auth123");

        // When
        Order result = orderService.createOrder(accountId, request);

        // Then
        assertNotNull(result);
        assertEquals(accountId, result.getAccountId());
        assertEquals(Order.OrderStatus.PENDING, result.getStatus());
        assertEquals(1, result.getIdentifiers().size());
        assertEquals("dns", result.getIdentifiers().get(0).getType());
        assertEquals("example.com", result.getIdentifiers().get(0).getValue());
        assertNotNull(result.getAuthorizations());
        assertEquals(1, result.getAuthorizations().size());
    }
}