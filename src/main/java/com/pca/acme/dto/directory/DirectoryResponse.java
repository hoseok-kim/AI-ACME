package com.pca.acme.dto.directory;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DirectoryResponse {
    @JsonProperty("newNonce")
    private String newNonce;
    
    @JsonProperty("newAccount")
    private String newAccount;
    
    @JsonProperty("newOrder")
    private String newOrder;
    
    @JsonProperty("revokeCert")
    private String revokeCert;
    
    @JsonProperty("keyChange")
    private String keyChange;
    
    @JsonProperty("meta")
    private DirectoryMeta meta;      // RFC 8555 §7.1.1
}
