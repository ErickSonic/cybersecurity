package com.ciberseguridad.api.model;

import java.util.HashMap;
import java.util.List;

import lombok.Data;

@Data
public class NmapPorts extends Nmap{

	private List<HashMap<String,String>> ports;

	public NmapPorts() {
		super();
	}
	
	public NmapPorts(List<HashMap<String, String>> ports) {
		super();
		this.ports = ports;
	}

	public List<HashMap<String, String>> getPorts() {
		return ports;
	}

	public void setPorts(List<HashMap<String, String>> ports) {
		this.ports = ports;
	}
}