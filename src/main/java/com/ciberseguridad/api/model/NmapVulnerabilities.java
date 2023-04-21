package com.ciberseguridad.api.model;

import java.util.HashMap;
import java.util.List;

import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Data;

@Document(collection = "nmap")
@Data
public class NmapVulnerabilities extends Nmap{

	private List<HashMap<String,String>> vulnerabilities;

	public NmapVulnerabilities() {
		super();
	}
	
	public NmapVulnerabilities(List<HashMap<String, String>> vulnerabilities) {
		super();
		this.vulnerabilities = vulnerabilities;
	}
	
}
