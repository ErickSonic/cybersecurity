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
	
	public Nmap saveScan(String scanType, RequestModel req) throws IOException {
		switch(scanType) {
//			case "tcp":{
//				nmap = new NmapVulnerabilities();
//				nmap.setScriptId("tcp");
//				nmap.setScriptDescription("Escaneo de puertos TCP");
//				nmap.setResultado(scriptService.processScript("nmap -sS -sV -T4 " + req.getDomain()));
//				break;
//			}
			case "vulnerabilities":{
				NmapVulnerabilities nmap = new NmapVulnerabilities();
				nmap.setScriptId("vulnerabilities");
			    nmap.setScriptDescription("Escaneo de vulnerabilidades");
				nmap.setResultado(scriptService.processScript("nmap -Pn -sV --script vuln " + req.getDomain()));
				nmap.setVulnerabilities(scriptService.processVulnerabilitiesScript("nmap -Pn -sV --script vuln " + req.getDomain()));
//				nmap.setResultado(scriptService.processScript("ping -n 3 " + req.getDomain()));
//				HashMap<String,List<HashMap<String,String>>> vuln = new HashMap<String,List<HashMap<String,String>>>();
//				List<HashMap<String,String>> list = Collections.synchronizedList(new ArrayList<HashMap<String,String>>());
//		        HashMap<String,String> mapa = new HashMap<String, String>();
		        
//		        mapa.put("hola","hola");
//			    mapa.put("hola2","hola2");
//		        list.add(mapa);
//			    list.add(mapa);
//			    vuln.put("8/tcp", list);
//			    list = new ArrayList<HashMap<String,String>>();
//			    list.add(mapa);
//			    vuln.put("9/tcp", list);
//				nmap.setVulnerabilities(vuln);
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
//				nmap.setResultado(scriptService.processScript("nmap -sU " + req.getDomain()));
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
