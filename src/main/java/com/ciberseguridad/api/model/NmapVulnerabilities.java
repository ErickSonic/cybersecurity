package com.ciberseguridad.api.model;

import java.util.HashMap;
import java.util.List;

import lombok.Data;

@Data
public class NmapVulnerabilities extends Nmap{

	private HashMap<String,List<HashMap<String,String>>> vulnerabilities;

	public NmapVulnerabilities() {
		super();
	}
	
	public NmapVulnerabilities(HashMap<String,List<HashMap<String,String>>> vulnerabilities) {
		super();
		this.vulnerabilities = vulnerabilities;
	}

	public HashMap<String,List<HashMap<String,String>>> getVulnerabilities() {
		return vulnerabilities;
	}

	public void setVulnerabilities(HashMap<String,List<HashMap<String,String>>> vulnerabilities) {
		this.vulnerabilities = vulnerabilities;
	}
}