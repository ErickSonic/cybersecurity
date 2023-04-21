package com.ciberseguridad.api.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Data;

@Document(collection = "nmap")
@Data
public abstract class Nmap {
	
	@Id
	private String id;
	private String scriptId;
	private String scriptDescription;
	private String resultado;
	
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public String getScriptId() {
		return scriptId;
	}
	public void setScriptId(String scriptId) {
		this.scriptId = scriptId;
	}
	public String getScriptDescription() {
		return scriptDescription;
	}
	public void setScriptDescription(String scriptDescription) {
		this.scriptDescription = scriptDescription;
	}
	public String getResultado() {
		return resultado;
	}
	public void setResultado(String resultado) {
		this.resultado = resultado;
	}
	
}
