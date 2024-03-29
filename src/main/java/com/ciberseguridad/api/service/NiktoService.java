package com.ciberseguridad.api.service;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ciberseguridad.api.model.Nikto;
import com.ciberseguridad.api.model.RequestModel;
import com.ciberseguridad.api.repository.NiktoRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class NiktoService {

	@Autowired
	private NiktoRepository niktoRepository;
	
	@Autowired
	private ScanningScriptService scriptService;

	public <S extends Nikto> S save(S entity) {
		return niktoRepository.save(entity);
	}

	public List<Nikto> findAll() {
		return niktoRepository.findAll();
	}

	public Optional<Nikto> findById(String id) {
		return niktoRepository.findById(id);
	}
	
	public List<Nikto> findByScriptId(String scriptId) {
		return niktoRepository.findByScriptId(scriptId);
	}

	public void deleteById(String id) {
		niktoRepository.deleteById(id);
	}
	
	public Nikto saveScan(String scanType, RequestModel req) throws IOException {
		Nikto nikto = new Nikto();
		switch(scanType) {
			case "webServer":{
				nikto.setScriptId("webServer");
				nikto.setScriptDescription("Escaneo de vulnerabilidades en servidor web");
				nikto.setResultado(scriptService.processScript("nikto -h " + req.getDomain()));
				break;
			}
			case "ssl":{
				nikto.setScriptId("ssl");
				nikto.setScriptDescription("Escaneo de vulnerabilidades en servidor web SSL");
				nikto.setResultado(scriptService.processScript("nikto -h " + req.getDomain() + " -ssl"));
				break;
			}
			case "autenticacion":{
				nikto.setScriptId("autentication");
				nikto.setScriptDescription("Escaneo de vulnerabilidades en servidor web usando autenticación");
				nikto.setResultado(scriptService.processScript("nikto -h " + req.getDomain() + " -id admin:password"));
				break;
			}
			case "proxy":{
				nikto.setScriptId("proxy");
				nikto.setScriptDescription("Escaneo de vulnerabilidades en servidor web usando proxyP");
				nikto.setResultado(scriptService.processScript("nikto -h " + req.getDomain() + " -useproxy http://proxy.example.com:8080"));
				break;
			}
		}
		return niktoRepository.save(nikto);
	}
}
