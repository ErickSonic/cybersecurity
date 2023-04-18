package com.ciberseguridad.api.controller;

import java.net.URI;
import java.util.List;

import javax.persistence.EntityNotFoundException;

import org.apache.catalina.connector.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.ciberseguridad.api.model.Nmap;
import com.ciberseguridad.api.service.NmapService;

@RestController
@RequestMapping(value = "/api/nmap")
public class NmapController {

	@Autowired
	private NmapService nmapService;
	
	@GetMapping
	private ResponseEntity<List<Nmap>> findAll() {
		return ResponseEntity.ok(nmapService.findAll());
	}
	
	@GetMapping("{id}")
	private ResponseEntity<Nmap> findById(@PathVariable String id) {
		Nmap nmap = nmapService.findById(id).orElseThrow(() -> new EntityNotFoundException("Escaneo no encontrado"));
		return ResponseEntity.ok(nmap);
	}
	
	@GetMapping(params = "scriptId")
	private ResponseEntity<List<Nmap>> findByScriptId(@RequestParam String scriptId) {
		return ResponseEntity.ok(nmapService.findByScriptId(scriptId));
	}
	
	@PostMapping
	private ResponseEntity<Nmap> save(@RequestBody Nmap nmap) {
		try {
			Nmap nmapSaved = nmapService.save(nmap);
			return ResponseEntity.created(new URI("/api/nmap/" + nmapSaved.getId())).body(nmapSaved);
		} catch (Exception e) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
		}
	}
	
	@PostMapping(params = "scriptId")
	private ResponseEntity<Nmap> saveScan(@RequestParam String scriptId, @RequestBody String domain) {
		try {
			Nmap nmapSaved = nmapService.saveScan(scriptId, domain);
			return ResponseEntity.created(new URI("/api/nmap/" + nmapSaved.getId())).body(nmapSaved);
		} catch (Exception e) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
		}
	}
	
	@DeleteMapping("{id}")
	private ResponseEntity<List<Nmap>> deleteById(@PathVariable String id) {
		nmapService.deleteById(id);
		return ResponseEntity.ok(nmapService.findAll());
	}
}
