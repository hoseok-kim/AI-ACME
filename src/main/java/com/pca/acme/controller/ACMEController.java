package com.pca.acme.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.http.HttpHeaders;

import com.pca.acme.dto.directory.DirectoryResponse;
import com.pca.acme.service.DirectoryService;
import com.pca.acme.service.NonceService;

@RestController
@RequiredArgsConstructor
@RequestMapping("/acme")
@CrossOrigin(origins = "*")
public class ACMEController {

    private final DirectoryService directoryService;
    private final NonceService nonceService;

    /**
     * RFC 8555 §7.1 Directory 엔드포인트
     * ACME 클라이언트가 처음 호출해야 하는 엔드포인트
     */
    @GetMapping(
        value = "/directory",
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public DirectoryResponse directory() {
        return directoryService.getDirectory();
    }

    /**
     * RFC 8555 §7.2 NewNonce 엔드포인트
     * HEAD 메서드 (권장) - 200 OK 반환
     */
    @RequestMapping(value = "/new-nonce", method = RequestMethod.HEAD)
    public ResponseEntity<Void> newNonceHead() {
        String nonce = nonceService.createNonce();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Replay-Nonce", nonce);
        headers.add("Cache-Control", "no-store");
        headers.add("Link", "<" + nonceService.getDirectoryUrl() + ">;rel=\"index\"");
        
        return ResponseEntity.ok().headers(headers).build();
    }

    /**
     * RFC 8555 §7.2 NewNonce 엔드포인트
     * GET 메서드 (선택) - 204 No Content 반환
     */
    @GetMapping("/new-nonce")
    public ResponseEntity<Void> newNonceGet() {
        String nonce = nonceService.createNonce();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Replay-Nonce", nonce);
        headers.add("Cache-Control", "no-store");
        headers.add("Link", "<" + nonceService.getDirectoryUrl() + ">;rel=\"index\"");
        
        return ResponseEntity.noContent().headers(headers).build();
    }
} 