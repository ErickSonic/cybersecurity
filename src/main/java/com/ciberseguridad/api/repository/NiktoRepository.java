package com.ciberseguridad.api.repository;

import java.util.List;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import com.ciberseguridad.api.model.Nikto;

@Repository
public interface NiktoRepository extends MongoRepository<Nikto, String>{

	@Query("{ 'scriptId' : ?0 }")
	List<Nikto> findByScriptId(String scriptId);
}
