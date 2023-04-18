package com.ciberseguridad.api.repository;

import java.util.List;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import com.ciberseguridad.api.model.Nmap;

@Repository
public interface NmapRepository extends MongoRepository<Nmap, String>{

	@Query("{ 'scriptId' : ?0 }")
	List<Nmap> findByScriptId(String scriptId);
}
