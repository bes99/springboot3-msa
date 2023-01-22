package com.example.catalogsservice.controller;

import com.example.catalogsservice.jpa.CatalogEntity;
import com.example.catalogsservice.service.CatalogService;
import com.example.catalogsservice.vo.ResponseCatalog;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/catalog-service")
@AllArgsConstructor
public class CatalogController {
    private final Environment env;
    private final CatalogService catalogService;

    @GetMapping("/health_check")
    public String status(){
        return String.format("It's Working in Catalog Service On PORT %s",
                env.getProperty("local.server.port"));
    }

    @GetMapping("/catalogs")
    public ResponseEntity<List<ResponseCatalog>> getCatalogs(){
        Iterable<CatalogEntity> catalogList = catalogService.getAllCatalogs();
        List<ResponseCatalog> result = new ArrayList<>();
        catalogList.forEach(v ->{
            result.add(new ModelMapper().map(v,ResponseCatalog.class));
        });
        return ResponseEntity.status(HttpStatus.OK).body(result);
    }
}
