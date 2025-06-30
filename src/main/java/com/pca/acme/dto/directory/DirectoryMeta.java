package com.pca.acme.dto.directory;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DirectoryMeta {
    private String termsOfService;
    private String website;
    private List<String> caaIdentities;
    private boolean externalAccountRequired;
} 