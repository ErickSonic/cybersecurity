package com.ciberseguridad.api.service;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ciberseguridad.api.model.Nmap;
import com.ciberseguridad.api.repository.NmapRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class NmapService {
	@Autowired
	private NmapRepository nmapRepository;
	
	@Autowired
	private ScanningScriptService scriptService;

	public <S extends Nmap> S save(S entity) {
		return nmapRepository.save(entity);
	}

	public List<Nmap> findAll() {
		return nmapRepository.findAll();
	}

	public Optional<Nmap> findById(String id) {
		return nmapRepository.findById(id);
	}
	
	public List<Nmap> findByScriptId(String scriptId) {
		return nmapRepository.findByScriptId(scriptId);
	}

	public void deleteById(String id) {
		nmapRepository.deleteById(id);
	}
	
	public Nmap saveScan(String scanType, String domain) throws IOException {
		Nmap nmap = new Nmap();
		switch(scanType) {
			case "tcp":{
				nmap.setScriptId("tcp");
				nmap.setScriptDescription("Escaneo de puertos TCP");
				nmap.setResultado(scriptService.processScript("ping -n 3 " + domain));
				//nmap.setResultado(scriptService.processScript("nmap -sS -sV -T4 -oN archivo_salida.txt um.edu.mx"));
				break;
			}
			case "vulnerabilities":{
				nmap.setScriptId("vulnerabilities");
				nmap.setScriptDescription("Escaneo de puertos vulnerabilidades");
				nmap.setResultado(scriptService.processScript("nmap -Pn -sV --script vuln -oN salida2.txt " + domain));
				break;
			}
			case "service&so":{
				nmap.setScriptId("service&so");
				nmap.setScriptDescription("Escaneo de servicios y sistema operativo");
				nmap.setResultado(scriptService.processScript("nmap -A -oN salida3.txt " + domain));
				break;
			}
			case "udp":{
				nmap.setScriptId("udp");
				nmap.setScriptDescription("Escaneo de puertos UDP");
				nmap.setResultado(scriptService.processScript("nmap -sU -oN salida4.txt " + domain));
				break;
			}
			case "internalN":{
				nmap.setScriptId("internalN");
				nmap.setScriptDescription("Escaneo de red interna");
				nmap.setResultado(scriptService.processScript("nmap -sn -oN salida5.txt " + domain));
				break;
			}
		}
		return nmapRepository.save(nmap);
	}
}
