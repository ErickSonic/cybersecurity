package com.ciberseguridad.api.service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class NmapScanningScriptService extends ScanningScriptService{
	
	public List<HashMap<String,String>> processTCPPortScript(String script) throws IOException{
		ProcessBuilder processBuilder = new ProcessBuilder();
		
		//processBuilder.command("cmd.exe", "/c", script);
	    processBuilder.command("bash", "-c", script);
	
	    try {
	
	        Process process = processBuilder.start();
	
	        List<HashMap<String,String>> ports = new ArrayList<HashMap<String,String>>();
	        HashMap<String,String> map = new HashMap<String, String>();
	
	        BufferedReader reader = new BufferedReader(
	                new InputStreamReader(process.getInputStream()));
	
	        String line;
	        while ((line = reader.readLine()) != null) {
	        	if(line.contains("/tcp")) {
	        		String featuresArr[] = line.split(" ");
	        		int iter = 0;
	        		for(String feature: featuresArr) {
	        			if(!(feature == "")) {
	        				switch(iter) {
	        					case 0:{
	        						map.put("port", feature);
	        						iter++;
	        						break;
	        					}
	        					case 1:{
	        						map.put("state", feature);
	        						iter++;
	        						break;
	        					}
	        					case 2:{
	        						map.put("service", feature);
	        						iter++;
	        						break;
	        					}
	        					case 3:{
	        						map.put("version", feature);
	        						iter++;
	        						break;
	        					}
	        				}
	        			}
	        		}
	        		ports.add(map);
	        	}
	        }
	        return ports;
	
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
	        List<HashMap<String,String>> list = new ArrayList<HashMap<String,String>>();
	        HashMap<String,String> map = new HashMap<String, String>();
	        String portId = "";
	
	        BufferedReader reader = new BufferedReader(
	                new InputStreamReader(process.getInputStream()));
	
	        String line;
	        while ((line = reader.readLine()) != null) {
	        	if(line.contains("CVE-") && line.contains("https://vulners.com/cve")) {
	        		line = line.substring(line.indexOf("CVE-"),line.indexOf("https://vulners.com/cve"));
	        		@SuppressWarnings("deprecation")
					String substrings[] = line.split(new Character((char) 9).toString());
					map.put("id", substrings[0]);
					map.put("evaluation", substrings[1]);
					list.add(map);
					map = new HashMap<String, String>();
	        	}
	        	else if(line.contains("/tcp")) {
					if (!(portId.equals("")) && !(list.isEmpty())) {
						vulnerabilities.put(portId, list);
						list = new ArrayList<HashMap<String, String>>();
						map = new HashMap<String, String>();
						portId = line.split(" ")[0];
					} else {
						portId = line.split(" ")[0];
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
