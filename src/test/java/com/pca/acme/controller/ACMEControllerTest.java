package com.pca.acme.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(ACMEController.class)
public class ACMEControllerTest {
    @Autowired
    MockMvc mockMvc;

    @Test
    void directory_shouldReturnJson() throws Exception {
        mockMvc.perform(get("/acme/directory"))
            .andExpect(status().isOk())
            .andExpect(content().contentType("application/json"))
            .andExpect(jsonPath("$.newNonce").exists())
            .andExpect(jsonPath("$.meta").exists());
    }
}
