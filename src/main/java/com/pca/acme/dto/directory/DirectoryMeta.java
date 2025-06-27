package com.pca.acme.dto.directory;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)    // null 필드는 JSON에 포함 X
@Builder
public record DirectoryMeta(
    String termsOfService,
    String website,
    List<String> caaIdentities,
    boolean externalAccountRequired
) {}
