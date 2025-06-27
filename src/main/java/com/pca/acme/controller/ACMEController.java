package com.pca.acme.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.pca.acme.dto.directory.DirectoryResponse;
import com.pca.acme.service.DirectoryService;

@RestController
@RequiredArgsConstructor
@RequestMapping("/acme")     // 공통 Prefix – 프록시에서 /.well-known/acme-directory로 매핑해도 OK
public class ACMEController {

    private final DirectoryService directoryService;

    /**
     * RFC 8555 §7.1 Directory 엔드포인트
     */
    @GetMapping(
        value = "/directory",
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public DirectoryResponse directory() {
        return directoryService.getDirectory();
    }
}
