package com.ciberseguridad.api.service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class NmapScanningScriptService {
	
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
	            output.append(line + "\n");
	        }
	
	        return output.toString();
	
	    } catch (IOException e) {
	        e.printStackTrace();
	        throw e;
	    }
	}
	
	public HashMap<String,List<HashMap<String,String>>> processVulnerabilitiesScript(String script) throws IOException{
		ProcessBuilder processBuilder = new ProcessBuilder();
		
		//processBuilder.command("cmd.exe", "/c", script);
	    processBuilder.command("bash", "-c", script);
	
	    try {
	
	        Process process = processBuilder.start();
	
	        HashMap<String,List<HashMap<String,String>>> vulnerabilities = new HashMap<String,List<HashMap<String,String>>>();
	        String portId = "";
	        List<HashMap<String,String>> list = new ArrayList<HashMap<String,String>>();
	        HashMap<String,String> map = new HashMap<String, String>();
	
	        BufferedReader reader = new BufferedReader(
	                new InputStreamReader(process.getInputStream()));
	
	        String line;
	        while ((line = reader.readLine()) != null) {
	        	if(line.contains("CVE-")) {
	        		String substrings[] = line.split(" ");
	        		for(int i = 0; i<substrings.length; i++){
						if(substrings[i].contains("CVE-") && !substrings[i].contains("/CVE-") && (i+4<substrings.length)) {
							map.put("id", substrings[i]);
							map.put("evaluation", substrings[i+4]);
							list.add(map);
						}
	        		}
	        	}
	        	else if(line.contains("/tcp")) {
	        		String substrings[] = line.split(" ");
		            for(String i: substrings){
	                    if(i.contains("/tcp")){
	                        if(!vulnerabilities.isEmpty()) {
	                        	vulnerabilities.put(portId,list);
	                        	list = new ArrayList<HashMap<String,String>>();
	                        	map = new HashMap<String, String>();
	                        	portId = i;
	                        }
	                        else {
	                        	portId = i;
	                        }
	                    }
	                }
	        	}
	        }
	        return vulnerabilities;
	
	    } catch (IOException e) {
	        e.printStackTrace();
	        throw e;
	    }
	}
}
