package com.ciberseguridad.api.config;

import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.core.mapping.event.BeforeConvertCallback;

import com.ciberseguridad.api.model.UuidIdentifiedEntity;

@Configuration
public class EntityCallbackMongoConfig {
    
    @Bean
    public BeforeConvertCallback<UuidIdentifiedEntity> beforeSaveCallback() {
        
        return (entity, collection) -> {
          
            if(entity.getId() == null) {
                entity.setId(UUID.randomUUID());
            }
            return entity;
        };        
    }
    
}