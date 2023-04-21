package com.ciberseguridad.api.service;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ciberseguridad.api.model.Nmap;
import com.ciberseguridad.api.model.NmapVulnerabilities;
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
		
		switch(scanType) {
			case "tcp":{
				Nmap nmap = new NmapVulnerabilities();
				nmap.setScriptId("tcp");
				nmap.setScriptDescription("Escaneo de puertos TCP");
				nmap.setResultado(scriptService.processScript("nmap -sS -sV -T4 " + domain));
				//nmap.setResultado(scriptService.processScript("ping -n 3 " + domain));
				break;
			}
//			case "vulnerabilities":{
//				nmap.setScriptId("vulnerabilities");
//				nmap.setScriptDescription("Escaneo de vulnerabilidades");
//				nmap.setResultado(scriptService.processScript("nmap -Pn -sV --script vuln " + domain));
//				break;
//			}
//			case "serviceso":{
//				nmap.setScriptId("serviceso");
//				nmap.setScriptDescription("Escaneo de servicios y sistema operativo");
//				nmap.setResultado(scriptService.processScript("nmap -A " + domain));
//				break;
//			}
//			case "udp":{
//				nmap.setScriptId("udp");
//				nmap.setScriptDescription("Escaneo de puertos UDP");
//				nmap.setResultado(scriptService.processScript("nmap -sU " + domain));
//				break;
//			}
//			case "internalN":{
//				nmap.setScriptId("internalN");
//				nmap.setScriptDescription("Escaneo de red interna");
//				nmap.setResultado(scriptService.processScript("nmap -sn " + domain));
//				break;
//			}
		}
		return nmapRepository.save(nmap);
	}
}
