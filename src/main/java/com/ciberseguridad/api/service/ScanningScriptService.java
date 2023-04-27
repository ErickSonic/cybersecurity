package com.ciberseguridad.api.service;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public abstract class ScanningScriptService {
	public String processScript(String script) throws IOException{
        ProcessBuilder processBuilder = new ProcessBuilder();
        
	    //processBuilder.command("cmd.exe", "/c", script);
	    processBuilder.command("bash", "-c", script);
	
	    try {
	
	        Process process = processBuilder.start();
	
	        StringBuilder output = new StringBuilder();
	
	        BufferedReader reader = new BufferedReader(
	                new InputStreamReader(process.getInputStream()));
	
	        String line;
	        while ((line = reader.readLine()) != null) {
	            output.append(line + System.getProperty("line.separator"));
	        }
	
	        return output.toString();
	
	    } catch (IOException e) {
	        e.printStackTrace();
	        throw e;
	    }
	}
}
