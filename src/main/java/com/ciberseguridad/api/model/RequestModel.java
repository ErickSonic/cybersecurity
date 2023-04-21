package com.ciberseguridad.api.model;

import lombok.Data;

@Data
public class RequestModel {

	private String domain;
	private String domain2;

	public String getDomain() {
		return domain;
	}

	public void setDomain(String domain) {
		this.domain = domain;
	}

	public String getDomain2() {
		return domain2;
	}

	public void setDomain2(String domain2) {
		this.domain2 = domain2;
	}
	
}