package com.ciberseguridad.api.service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ciberseguridad.api.model.Nmap;
import com.ciberseguridad.api.model.NmapPorts;
import com.ciberseguridad.api.model.NmapVulnerabilities;
import com.ciberseguridad.api.model.RequestModel;
import com.ciberseguridad.api.repository.NmapRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class NmapService {
	@Autowired
	private NmapRepository nmapRepository;
	
	@Autowired
	private NmapScanningScriptService scriptService;

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
	
	@SuppressWarnings("unchecked")
	public Nmap saveScan(String scanType, RequestModel req) throws IOException {
		switch(scanType) {
			case "tcp":{
				NmapPorts nmap = new NmapPorts();
				Object[] processedInfo = scriptService.processTCPPortScript("nmap -Pn -sV --script vuln " + req.getDomain());
				nmap.setScriptId("tcp");
				nmap.setScriptDescription("Escaneo de puertos TCP");
				nmap.setResultado(processedInfo[0].toString());
				nmap.setPorts((List<HashMap<String, String>>) processedInfo[1]);
				return nmapRepository.save(nmap);
			}
			case "vulnerabilities":{
				NmapVulnerabilities nmap = new NmapVulnerabilities();
				Object[] processedInfo = scriptService.processVulnerabilitiesScript("nmap -Pn -sV --script vuln " + req.getDomain());
				nmap.setScriptId("vulnerabilities");
			    nmap.setScriptDescription("Escaneo de vulnerabilidades");
				nmap.setResultado(processedInfo[0].toString());
				nmap.setVulnerabilities((HashMap<String, List<HashMap<String, String>>>) processedInfo[1]);
//				nmap.setResultado(scriptService.processScript("ping -n 3 " + req.getDomain()));
				return nmapRepository.save(nmap);
			}
//			case "serviceso":{
//				nmap.setScriptId("serviceso");
//				nmap.setScriptDescription("Escaneo de servicios y sistema operativo");
//				nmap.setResultado(scriptService.processScript("nmap -A " + req.getDomain()));
//				break;
//			}
//			case "udp":{
//				nmap.setScriptId("udp");
//				nmap.setScriptDescription("Escaneo de puertos UDP");
//				nmap.setResultado(scriptService.processScript("sudo nmap -sU " + req.getDomain()));
//				break;
//			}
//			case "internalN":{
//				nmap.setScriptId("internalN");
//				nmap.setScriptDescription("Escaneo de red interna");
//				nmap.setResultado(scriptService.processScript("nmap -sn " + req.getDomain()));
//				break;
//			}
			default:{
				Nmap nmap = new Nmap();
				nmap = null;
				return nmapRepository.save(nmap);
			}
		}
	}
}
