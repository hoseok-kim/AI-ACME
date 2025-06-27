package com.pca.acme.dto.directory;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record DirectoryResponse(
    @JsonProperty("newNonce")      String newNonce,
    @JsonProperty("newAccount")    String newAccount,
    @JsonProperty("newOrder")      String newOrder,
    @JsonProperty("revokeCert")    String revokeCert,
    @JsonProperty("keyChange")     String keyChange,
    @JsonProperty("meta")          DirectoryMeta meta      // RFC 8555 §7.1.1
) {}
