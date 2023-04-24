package com.ciberseguridad.api.controller;

import java.net.URI;
import java.util.List;

import javax.persistence.EntityNotFoundException;

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

import com.ciberseguridad.api.model.Nikto;
import com.ciberseguridad.api.model.RequestModel;
import com.ciberseguridad.api.service.NiktoService;

@RestController
@RequestMapping(value = "/api/nikto")
public class NiktoController {

	@Autowired
	private NiktoService niktoService;
	
	@GetMapping
	private ResponseEntity<List<Nikto>> findAll() {
		return ResponseEntity.ok(niktoService.findAll());
	}
	
	@GetMapping("{id}")
	private ResponseEntity<Nikto> findById(@PathVariable String id) {
		Nikto nikto = niktoService.findById(id).orElseThrow(() -> new EntityNotFoundException("Escaneo no encontrado"));
		return ResponseEntity.ok(nikto);
	}
	
	@GetMapping(params = "scriptId")
	private ResponseEntity<List<Nikto>> findByScriptId(@RequestParam String scriptId) {
		return ResponseEntity.ok(niktoService.findByScriptId(scriptId));
	}
	
	@PostMapping
	private ResponseEntity<Nikto> save(@RequestBody Nikto nikto) {
		try {
			Nikto niktoSaved = niktoService.save(nikto);
			return ResponseEntity.created(new URI("/api/nikto/" + niktoSaved.getId())).body(niktoSaved);
		} catch (Exception e) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
		}
	}
	
	@PostMapping(params = "scriptId")
	private ResponseEntity<Nikto> saveScan(@RequestParam String scriptId, @RequestBody RequestModel req) {
		try {
			Nikto niktoSaved = niktoService.saveScan(scriptId, req);
			return ResponseEntity.created(new URI("/api/nikto/" + niktoSaved.getId())).body(niktoSaved);
		} catch (Exception e) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
		}
	}
	
	@DeleteMapping("{id}")
	private ResponseEntity<List<Nikto>> deleteById(@PathVariable String id) {
		niktoService.deleteById(id);
		return ResponseEntity.ok(niktoService.findAll());
	}
}
