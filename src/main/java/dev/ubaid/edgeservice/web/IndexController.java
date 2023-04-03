package dev.ubaid.edgeservice.web;

import dev.ubaid.edgeservice.config.ClientProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
@RequiredArgsConstructor
public class IndexController {
    
    private final ClientProperties clientProperties;
    
    @GetMapping
    public String index() {
        return clientProperties.homeMessage();
    }
}
